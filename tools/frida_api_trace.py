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


# --- behaviour gate (RevAI handoff item 9) ---------------------------------
# The 2026-09-11 measurement: a 45 s window produced 497 Frida events and no
# DGA; a 150 s window produced 694,692 events and live HTTP POST C2. A fixed
# guess therefore decides, by coin flip, whether a run sees the behaviour that
# made the sample interesting. The gate makes the window follow the sample:
# keep tracing until it does something notable, then let it settle.
NETWORK_GATES = frozenset({
    "connect", "connectex", "wsaconnect", "wsasend", "wsasendto",
    "send", "sendto", "recv", "recvfrom",
    "internetopena", "internetopenaurl", "internetopenw", "internetopenurla",
    "internetconnecta", "internetconnectw", "internetreadfile",
    "winhttpopen", "winhttpconnect", "winhttpsendrequest",
    "winhttpreceiveresponse", "winhttpquerydataavailable",
    "httpopenrequesta", "httpopenrequestw", "httpsendrequesta",
    "httpsendrequestw", "httpqueryinfoa",
    "urldownloadtofilea", "urldownloadtofilew",
    "getaddrinfo", "gethostbynamea", "gethostbynamew",
})
FILE_GATES = frozenset({
    "createfilew", "createfilea", "ntcreatefile", "zwcreatefile",
    "writefile", "writefileex", "ntwritefile", "zwwritefile",
    "movefilew", "movefilea", "movefileexw", "copyfilew", "copyfilea",
    "deletefilew", "deletefilea", "ntdeletefile", "setfileattributesw",
    "regcreatekeyw", "regsetvaluew", "regcreatekeyexw",
})


def parse_stop_on(spec):
    """'network,file,api:WinHttpOpen' -> ({'network','file'}, {'WINHTTPOPEN'})."""
    kinds, apis = set(), set()
    for raw in (spec or "").split(","):
        t = raw.strip().lower()
        if not t:
            continue
        if t in ("network", "net", "socket"):
            kinds.add("network")
        elif t in ("file", "files", "drop", "dropper"):
            kinds.add("file")
        elif t.startswith("api:"):
            apis.add(t[4:].strip().upper())
    return kinds, apis


# A CreateFile is only a DROPPED file if it opens for WRITE. Reading a
# DLL, a resource or the locale sort table is not a drop: the first live
# dynamic run (P1 s01, 2026-10-06) tripped the file gate on
# CreateFileW("...\\Sorting\\sortdefault.nls", GENERIC_READ) at t=2.3s and
# collapsed a 150s window to 22.4s - reintroducing exactly the
# short-window truncation RevAI measured (behaviour gate, finding P1-F2).
CREATE_APIS = frozenset({"createfilew", "createfilea", "ntcreatefile",
                       "zwcreatefile"})
# GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES
WRITE_ACCESS_BITS = 0x40000000 | 0x00000002 | 0x00000004 | 0x00000100

# --- P1-F6: a payload drop is not "any write" (finding of 2026-10-06) -------
#
# b104 (WinX.OperationDianxun, a .NET loader) fired the file gate at t=1.1s
# on WriteFile and cut a 150s window to 2.8s, losing the memory dump - the
# single most valuable artefact for a reflective-loading sample. Resolving the
# handle offline from the same trace (pairing CreateFile onEnter with its
# onLeave retval) showed 0 of 9 WriteFile calls could be attributed to any
# file: all used handle 0xafc, never opened by a CreateFile we hook. That is a
# console/stdout handle - the program printing to the console.
#
# So the gate was firing on an UNPROVEN write. That is the same rule P1-F2
# fixed for CreateFile: never claim a drop you cannot prove. The gate now
# requires an attributable path, and that path must look like a payload drop
# or a destructive target.
#
# This still catches CWipeNew (b107), which opened \\.\PhysicalDrive0 through
# CreateFileW: a device path is always a destructive write.

# Executable / loadable / scriptable content: a drop by definition.
DROP_EXTS = frozenset({
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat",
    ".cmd", ".msi", ".msp", ".jar", ".lnk", ".pif", ".com", ".reg", ".inf",
})

# Build/runtime scratch a loader legitimately writes at startup. These only
# count when they land in a staging location (see DROP_DIRS).
SCRATCH_EXTS = frozenset({
    ".pdb", ".config", ".cache", ".ini", ".log", ".xml", ".json", ".dat",
    ".tmp", ".etl", ".evtx", ".txt", ".map", ".ilk", ".exp", ".lib", ".res",
    ".nls", ".mui", ".dll.aux",
})

# Classic drop / persistence / staging roots.
DROP_DIRS = (
    "\\appdata\\", "\\local\\", "\\roaming\\", "\\temp\\", "\\tmp\\",
    "\\programdata\\", "\\start menu\\", "\\startup\\", "\\system32\\",
    "\\syswow64\\", "\\sysnative\\", "\\program files\\",
    "\\program files (x86)\\", "\\public\\", "\\downloads\\",
    "\\users\\public\\", "\\windows\\temp\\", "\\$recycle.bin\\",
)


def _arg_int(args, i):
    """Frida hands pointer args through as hex strings; parse one."""
    try:
        v = args[i]
        return int(v, 16) if isinstance(v, str) else int(v)
    except Exception:
        return None


def classify_path(path):
    r"""Is this write a payload drop or a destructive act? -> gate kind or None.

    Returns "device" for raw device writes (\\.\PhysicalDriveN), "drop" for
    executable content or a write into a staging/persistence location, and
    None for runtime scratch or anything unrecognised. None means "do not
    claim a drop": an unproven gate hit truncates the observation window,
    which costs more than a late one.
    """
    if not path or not isinstance(path, str):
        return None
    low = path.replace("/", "\\").lower()
    if low.startswith("\\\\.\\") or low.startswith("\\device\\"):
        return "device"
    ext = low[low.rfind("."):] if "." in low.rsplit("\\", 1)[-1] else ""
    in_drop_dir = any(d in low for d in DROP_DIRS)
    if ext in DROP_EXTS:
        return "drop"
    if ext in SCRATCH_EXTS:
        # a scratch file only matters if it is being planted somewhere
        return "drop" if in_drop_dir else None
    if in_drop_dir:
        return "drop"
    return None


def gate_for(api, kinds, apis, args=None, path=None):
    """Which gate (if any) this call satisfies. Pure, so it is testable.

    `args` is the call's argument list and `path` is the target's path when
    the tracer could attribute the call to a file (see classify_path).

    Both are load-bearing, and absence degrades to NOT firing:
      * a Create*-style call without an access mask may be a read;
      * a Write*-style call without an attributable path may be a console
        write - that mistake cost b104 its memory dump (P1-F6).
    """
    if not api:
        return None
    name = str(api)
    if name.upper() in apis:
        return "api:" + name
    low = name.lower()
    if "network" in kinds and low in NETWORK_GATES:
        return "network"
    if "file" in kinds and low in FILE_GATES:
        if low in CREATE_APIS:
            acc = _arg_int(args, 1) if args and len(args) > 1 else None
            if acc is None:
                return None          # cannot prove a write
            if not (acc & WRITE_ACCESS_BITS):
                return None          # a READ, not a drop
            kind = classify_path(path)
            return kind              # may be None: an opened-for-write file
                                     # that is not a drop target
        # WriteFile and friends carry only a HANDLE. Without the tracer's
        # handle->path map there is no proof of what is being written.
        kind = classify_path(path)
        if kind is None:
            return None
        return kind
    return None


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
    ap.add_argument(
        "--idle-stop",
        type=int,
        default=0,
        help="adaptive window: stop early after N seconds without new events "
             "(0 = off; max-seconds stays the hard cap). OFF by default - see "
             "--stop-on: idle counts a sleeping sample as idle, so it cuts a "
             "sample off right before it wakes up and beacons.",
    )
    ap.add_argument(
        "--stop-on",
        default="network,file",
        help="behaviour gate: stop the window once the sample does something "
             "interesting and then goes quiet again. Comma-separated: "
             "network, file, or api:<ExportName>. Empty string disables.",
    )
    ap.add_argument(
        "--stop-on-settle",
        type=int,
        default=20,
        help="after the gate fires, keep tracing this many seconds so the "
             "follow-on activity is captured (the first outbound connect is "
             "rarely the interesting packet on its own), then stop.",
    )
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
// P1-F6: which argument is a FILE HANDLE we can resolve to a path.
// WriteFile/NtWriteFile take the handle in arg0; the path only exists in the
// handle->path map built when CreateFile* returned it.
const handleArgs = {{
  WriteFile: 0,
  WriteFileEx: 0,
  WriteFileGather: 0,
  NtWriteFile: 0,
  FlushFileBuffers: 0,
  SetFilePointer: 0,
  SetFilePointerEx: 0,
  LockFile: 0,
  UnlockFile: 0,
}};
const createApiSet = new Set(['CreateFileW', 'CreateFileA',
  'CreateFileTransactedW', 'CreateFileTransactedA', 'NtCreateFile',
  'ZwCreateFile']);
const closeApiSet = new Set(['CloseHandle']);
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
    // P1-F6: resolve a handle-taking API (WriteFile & co) back to the path
    // that handle was opened with. Without this a file write cannot be
    // attributed to any file, which is how the b104 gate fired on a console
    // write and cut its window to 2.8s, losing the memory dump.
    const hIdx = handleArgs[name];
    if (hIdx !== undefined && args[hIdx]) {{
        const known = handlePaths[args[hIdx].toString()];
        if (known) decoded['path'] = known;
    }}
    return {{ args: out, decoded: decoded }};
}}

// handle -> path, filled when a CreateFile* returns and cleared on
// CloseHandle so the map cannot grow unbounded across a long window.
const handlePaths = {{}};
const pendingPathByTid = {{}};

function rememberOpenedHandle(name, retval, tid) {{
    if (!createApiSet.has(name)) return;
    if (retval === null || retval === undefined) return;
    const rv = retval.toString();
    if (rv === '0x0' || rv === '0xffffffff' || rv === '-1') return;
    const p = pendingPathByTid[tid];
    if (p) handlePaths[rv] = p;
    pendingPathByTid[tid] = null;
}}

function forgetHandle(name, args) {{
    if (!closeApiSet.has(name) || !args || !args[0]) return;
    delete handlePaths[args[0].toString()];
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
                const tid = Process.getCurrentThreadId();
                const enriched = enrichArgs(name, args);
                // P1-F6: stash the path a CreateFile* is opening, so the
                // handle it returns can be resolved back to that path.
                if (createApiSet.has(name)) {{
                    pendingPathByTid[tid] = enriched.decoded['arg0']
                        || enriched.decoded['arg5'] || null;
                }}
                if (closeApiSet.has(name)) {{
                    forgetHandle(name, args);
                }}
                send({{
                    type: 'call',
                    ts: Date.now(),
                    api: name,
                    tid: tid,
                    args: enriched.args,
                    decoded: enriched.decoded
                }});
            }},
            onLeave: function (retval) {{
                rememberOpenedHandle(name, retval, Process.getCurrentThreadId());
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
    # shared, mutable time origin: the message handler can fire as soon as the
    # script loads, before the run loop assigns its own t_start
    t0 = {"t": time.time()}
    last = {"t": t0["t"]}
    gate_kinds, gate_apis = parse_stop_on(getattr(args, "stop_on", ""))
    gate_settle = max(0, int(getattr(args, "stop_on_settle", 20) or 0))
    gate = {"fired": False, "at_s": None, "kind": None, "api": None,
            "stop_at": None}

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
                last["t"] = time.time()
                # behaviour gate: first notable call arms a settle window, so
                # the follow-on traffic (the actual C2 POST, the dropped file's
                # contents) is still captured before we stop
                if not gate["fired"] and gate_kinds:
                    payload = msg.get("payload") or {}
                    if isinstance(payload, dict) and payload.get("type") == "call":
                        hit = gate_for(payload.get("api"), gate_kinds,
                                       gate_apis, payload.get("args"),
                                       path=(payload.get("decoded") or {}).get("path")
                                            or (payload.get("decoded") or {}).get("arg0"))
                        if hit:
                            now = time.time()
                            _dec = payload.get("decoded") or {}
                            gate.update({
                                "fired": True, "kind": hit,
                                "api": payload.get("api"),
                                # P1-F6: record the TARGET, not the handle.
                                # For a WriteFile arg0 is a HANDLE and the
                                # resolved path is what makes the hit
                                # auditable - an unattributable hit is what
                                # cost b104 its memory dump.
                                "path": _dec.get("path") or _dec.get("arg0"),
                                "arg0": _dec.get("arg0"),
                                "at_s": round(now - t0["t"], 1),
                                "stop_at": now + gate_settle,
                            })
                            print(f"gate fired: {hit} "
                                  f"({payload.get('api')} -> "
                                  f"{gate.get('path')}) at "
                                  f"{gate['at_s']}s; settling {gate_settle}s",
                                  file=sys.stderr)
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
    t_start = t0["t"]
    deadline = t_start + args.max_seconds
    idle_stop = int(getattr(args, "idle_stop", 0) or 0)
    stop_reason = "cap"
    try:
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                if session.is_detached:
                    stop_reason = "detached"
                    print("session detached (target exited)", file=sys.stderr)
                    break
            except Exception:
                stop_reason = "detached"
                break
            # gate + settle wins over the cap being reached: the sample did
            # something notable and then went quiet
            if gate["fired"] and gate["stop_at"] and time.time() >= gate["stop_at"]:
                stop_reason = "gate:" + str(gate["kind"])
                print(f"stopping after gate {gate['kind']} settled "
                      f"{gate_settle}s", file=sys.stderr)
                break
            if idle_stop and (time.time() - last["t"]) > idle_stop:
                stop_reason = "idle"
                print(f"idle-stop: no events for {idle_stop}s", file=sys.stderr)
                break
    except KeyboardInterrupt:
        stop_reason = "interrupted"
        print("interrupted; detaching", file=sys.stderr)
    try:
        with open(str(out_path) + ".run.json", "w", encoding="utf-8") as fh:
            json.dump({"stop_reason": stop_reason,
                       "elapsed_s": round(time.time() - t_start, 1),
                       "max_seconds": args.max_seconds,
                       "idle_stop_s": idle_stop,
                       "gate": sorted(gate_kinds),
                       "gate_apis": sorted(gate_apis),
                       "gate_settle_s": gate_settle,
                       "gate_fired": gate["fired"],
                       "gate_kind": gate["kind"],
                       "gate_api": gate["api"],
                       "gate_at_s": gate["at_s"]}, fh)
    except Exception:
        pass

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
