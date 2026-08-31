#!/usr/bin/env python3
r"""
frida_api_trace.py — Frida API tracing for Flare-VM dynamic analysis (Frida 17+).

Decodes WCHAR/ANSI string arguments for file/reg/network APIs so traces include
readable paths (V6.2 path-decode fix).

Usage (PowerShell on Flare-VM):
    python C:\tools\flarevm-deploy\dynamic\frida_api_trace.py ^
      --target C:\samples\foo.exe ^
      --apis "CreateFileW,VirtualAlloc,WriteProcessMemory" ^
      --out C:\samples\foo.trace.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="Frida API tracer for Flare-VM (Frida 17+)")
    ap.add_argument("--target", help="path to PE binary to spawn")
    ap.add_argument("--pid", type=int, help="PID to attach to (instead of --target)")
    ap.add_argument(
        "--apis",
        required=True,
        help="comma-separated API names (e.g. CreateFileW,VirtualAlloc)",
    )
    ap.add_argument("--module", default=None, help="unused (compat); hooks resolve globally")
    ap.add_argument("--out", required=True, help="output JSONL file")
    ap.add_argument("--max-calls", type=int, default=10000)
    ap.add_argument("--max-seconds", type=int, default=60)
    args = ap.parse_args()

    try:
        import frida
    except ImportError:
        print("FATAL: frida not installed. pip install frida frida-tools", file=sys.stderr)
        sys.exit(1)

    api_list = [a.strip() for a in args.apis.split(",") if a.strip()]
    if not api_list:
        print("FATAL: --apis is empty", file=sys.stderr)
        sys.exit(1)

    apis_js = ",\n        ".join(f'"{a}"' for a in api_list)
    # Path/string decode map: which arg indices are WCHAR* or CHAR*
    # Also sockaddr decoding for connect/sendto when possible.
    js = f"""
'use strict';
const apis = [
        {apis_js}
];
const maxCalls = {args.max_calls};
let callCount = 0;

// WCHAR* / CHAR* argument indices by API name
const wcharArgs = {{
  CreateFileW: [0],
  CreateFileA: [0],
  DeleteFileW: [0],
  DeleteFileA: [0],
  MoveFileW: [0, 1],
  MoveFileExW: [0, 1],
  CopyFileW: [0, 1],
  WriteFile: [],
  ReadFile: [],
  RegOpenKeyExW: [1],
  RegOpenKeyExA: [1],
  RegCreateKeyExW: [1],
  RegCreateKeyExA: [1],
  RegSetValueExW: [1],
  RegSetValueExA: [1],
  RegDeleteKeyW: [1],
  RegDeleteValueW: [1],
  LoadLibraryW: [0],
  LoadLibraryA: [0],
  LoadLibraryExW: [0],
  GetProcAddress: [1],
  CreateProcessW: [0, 1],
  CreateProcessA: [0, 1],
  WinHttpOpen: [0],
  WinHttpConnect: [1],
  WinHttpOpenRequest: [2, 3],
  InternetOpenW: [0],
  InternetOpenA: [0],
  InternetConnectW: [1],
  InternetConnectA: [1],
  InternetOpenUrlW: [1],
  HttpOpenRequestW: [2, 3],
  URLDownloadToFileW: [1, 2],
}};
const ansiArgs = {{
  CreateFileA: [0],
  DeleteFileA: [0],
  RegOpenKeyExA: [1],
  RegCreateKeyExA: [1],
  RegSetValueExA: [1],
  LoadLibraryA: [0],
  CreateProcessA: [0, 1],
  InternetOpenA: [0],
  InternetConnectA: [1],
  GetProcAddress: [1],
}};
// sockaddr* argument index by API name
const sockaddrArgs = {{
  connect: [1],
  connectEx: [1],
  WSAConnect: [1],
  sendto: [2],
  recvfrom: [2],
}};

function resolveExport(name) {{
    try {{
        if (typeof Module.findGlobalExportByName === 'function') {{
            return Module.findGlobalExportByName(name);
        }}
    }} catch (e) {{}}
    try {{
        return Module.findExportByName(null, name);
    }} catch (e2) {{
        return null;
    }}
}}

function safeReadUtf16(ptr) {{
    try {{
        if (!ptr || ptr.isNull()) return null;
        return ptr.readUtf16String();
    }} catch (e) {{
        return null;
    }}
}}

function safeReadUtf8(ptr) {{
    try {{
        if (!ptr || ptr.isNull()) return null;
        // ordinals for GetProcAddress are small integers, not pointers
        const asU = ptr.toUInt32 ? ptr.toUInt32() : parseInt(ptr);
        if (asU > 0 && asU < 0x10000) return null;
        return ptr.readUtf8String();
    }} catch (e) {{
        return null;
    }}
}}

function decodeSockAddr(ptr) {{
    try {{
        if (!ptr || ptr.isNull()) return null;
        const family = ptr.readU16();
        if (family === 2) {{ // AF_INET
            const port = ((ptr.add(2).readU8() << 8) | ptr.add(3).readU8());
            const a = ptr.add(4).readU8();
            const b = ptr.add(5).readU8();
            const c = ptr.add(6).readU8();
            const d = ptr.add(7).readU8();
            return a + '.' + b + '.' + c + '.' + d + ':' + port;
        }}
        return 'family=' + family;
    }} catch (e) {{
        return null;
    }}
}}

function enrichArgs(name, args) {{
    const out = [];
    const decoded = {{}};
    for (let i = 0; i < 4; i++) {{
        out.push(args[i] ? args[i].toString() : null);
    }}
    const wIdx = wcharArgs[name] || [];
    for (const i of wIdx) {{
        const s = safeReadUtf16(args[i]);
        if (s !== null) decoded['arg' + i] = s;
    }}
    const aIdx = ansiArgs[name] || [];
    for (const i of aIdx) {{
        if (decoded['arg' + i] !== undefined) continue;
        const s = safeReadUtf8(args[i]);
        if (s !== null) decoded['arg' + i] = s;
    }}
    const saIdx = sockaddrArgs[name] || [];
    for (const i of saIdx) {{
        const sa = decodeSockAddr(args[i]);
        if (sa) decoded['sockaddr' + i] = sa;
    }}
    return {{ args: out, decoded: decoded }};
}}

function attachApi(name) {{
    try {{
        const addr = resolveExport(name);
        if (!addr) {{
            send({{type: 'log', level: 'warn', msg: `API ${{name}} not found`}});
            return;
        }}
        Interceptor.attach(addr, {{
            onEnter: function (args) {{
                if (callCount >= maxCalls) return;
                callCount++;
                const enriched = enrichArgs(name, args);
                send({{
                    type: 'call',
                    ts: Date.now(),
                    api: name,
                    tid: Process.getCurrentThreadId(),
                    args: enriched.args,
                    decoded: enriched.decoded
                }});
            }},
            onLeave: function (retval) {{
                send({{
                    type: 'ret',
                    ts: Date.now(),
                    api: name,
                    tid: Process.getCurrentThreadId(),
                    retval: retval ? retval.toString() : null
                }});
            }}
        }});
        send({{type: 'log', level: 'info', msg: `hooked ${{name}}`}});
    }} catch (e) {{
        send({{type: 'log', level: 'error', msg: `hook ${{name}} failed: ${{e}}`}});
    }}
}}

apis.forEach(attachApi);
send({{type: 'log', level: 'info', msg: 'hooks installed'}});
"""

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    device = frida.get_local_device()
    spawned_pid = None

    if args.pid:
        print(f"attaching to pid={args.pid}", file=sys.stderr)
        session = device.attach(args.pid)
    elif args.target:
        print(f"spawning {args.target}", file=sys.stderr)
        if not Path(args.target).is_file():
            print(f"FATAL: target not found: {args.target}", file=sys.stderr)
            sys.exit(1)
        spawned_pid = device.spawn([args.target])
        session = device.attach(spawned_pid)
    else:
        print("FATAL: must specify --target or --pid", file=sys.stderr)
        sys.exit(1)

    script = session.create_script(js)
    out_fh = open(out_path, "w", encoding="utf-8")
    write_lock = threading.Lock()
    closed = {"done": False}

    def on_message(msg, data):
        if closed["done"]:
            return
        try:
            if msg["type"] == "send":
                with write_lock:
                    if closed["done"]:
                        return
                    out_fh.write(json.dumps(msg["payload"]) + "\n")
                    out_fh.flush()
            elif msg["type"] == "error":
                sys.stderr.write(f"[frida error] {msg.get('stack', msg)}\n")
        except Exception:
            pass

    def _hard_exit(code: int = 0) -> None:
        closed["done"] = True
        try:
            with write_lock:
                out_fh.flush()
                out_fh.close()
        except Exception:
            pass
        if spawned_pid is not None:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)

    def _watchdog() -> None:
        time.sleep(max(5, int(args.max_seconds) + 8))
        print("watchdog: forcing exit", file=sys.stderr)
        _hard_exit(0)

    threading.Thread(target=_watchdog, daemon=True).start()

    script.on("message", on_message)
    script.load()
    time.sleep(0.3)

    if spawned_pid is not None:
        device.resume(spawned_pid)

    print(f"tracing for up to {args.max_seconds}s (max {args.max_calls} calls)", file=sys.stderr)
    deadline = time.time() + args.max_seconds
    try:
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                if session.is_detached:
                    print("session detached (target exited)", file=sys.stderr)
                    break
            except Exception:
                break
    except KeyboardInterrupt:
        print("interrupted; detaching", file=sys.stderr)

    closed["done"] = True
    if spawned_pid is not None:
        try:
            device.kill(spawned_pid)
        except Exception:
            pass
    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass
    try:
        with write_lock:
            out_fh.flush()
            out_fh.close()
    except Exception:
        pass

    print(f"trace complete: {out_path}", file=sys.stderr)
    _hard_exit(0)


if __name__ == "__main__":
    main()
