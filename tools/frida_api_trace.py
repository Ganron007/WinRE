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


def gate_settle_pending(gate, now):
    """Whether a fired behavior gate still owns its observation window."""
    try:
        return bool(gate.get("fired") and gate.get("stop_at") is not None
                    and float(now) < float(gate["stop_at"]))
    except (AttributeError, TypeError, ValueError):
        return False


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


# --- loading a DLL: it cannot be spawned, it must be hosted ----------------

DLL_CHARACTERISTICS = 0x2000          # IMAGE_FILE_DLL


def _pe_info(path: str | os.PathLike) -> dict:
    """Is this a DLL, and what does it export? Reads the header only.

    b105 proved this matters: the corpus paths are hashes, so the extension
    tells you nothing. The FILE HEADER's Characteristics bit and the export
    directory do.
    """
    out: dict = {"is_dll": False, "machine": None, "bits": None,
                 "exports": [], "entry": None}
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x800)
    except OSError:
        return out
    if len(head) < 0x40 or head[:2] != b"MZ":
        return out
    try:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if not 0 < e_lfanew <= len(head) - 0x78:
            return out
        if head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return out
        chars = int.from_bytes(head[e_lfanew + 22:e_lfanew + 24], "little")
        out["is_dll"] = bool(chars & DLL_CHARACTERISTICS)
        machine = int.from_bytes(head[e_lfanew + 4:e_lfanew + 6], "little")
        out["machine"] = machine
        out["bits"] = {0x014C: 32, 0x8664: 64, 0xAA64: 64}.get(machine)
        # DataDirectory[0] (Export) lives at PEhdr+0x78 in the optional header
        opt = e_lfanew + 24
        if opt + 0x88 > len(head):
            return out
        exp_rva = int.from_bytes(head[opt + 0x70:opt + 0x78], "little")
        exp_size = int.from_bytes(head[opt + 0x78:opt + 0x80], "little")
        if not exp_rva:
            return out
        out["_exp_rva"] = exp_rva          # section-relative, resolved below
    except Exception:
        return out
    return out


def _exports(path: str | os.PathLike) -> list[str]:
    """Named exports, via pefile when available. Empty list means we cannot
    prove any - which must NOT be treated as "no exports exist"."""
    try:
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(str(path))
    except Exception:
        return []
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return []
        names = []
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols or []:
            n = getattr(sym, "name", None)
            if n:
                names.append(n.decode("utf-8", "replace")
                             if isinstance(n, bytes) else str(n))
        return names
    finally:
        try:
            pe.close()
        except Exception:
            pass


def _rundll32_path(bits: int | None) -> str:
    """The rundll32 that can actually load this DLL.

    A 64-bit rundll32 cannot load a 32-bit DLL and vice versa - the load fails
    with "%%1 is not a valid Win32 application" if you get it backwards. So the
    host is chosen by the TARGET's machine type, which is the same rule the
    x64dbg launcher already follows (P1-F1: 32-bit samples get the 32-bit
    debugger).
    """
    windir = os.environ.get("WINDIR", r"C:\Windows")
    if bits == 32:
        return rf"{windir}\SysWOW64\rundll32.exe"
    return rf"{windir}\System32\rundll32.exe"


def _launch_argv(target: str, forced_entry: str | None = None) -> tuple[list[str], str, str | None]:
    """Build the argv for the sample: direct for an executable, rundll32 for a DLL.

    Returns (argv, loader, entrypoint). A DLL is hosted by rundll32, which is
    what an analyst does; the DLL's own code runs in the same process and is
    hooked exactly as a direct spawn would be.
    """
    info = _pe_info(target)
    if not info.get("is_dll"):
        return [str(target)], "direct", None

    # Frida's device.spawn needs a resolvable path, not a bare image name -
    # "rundll32.exe" is looked up on the PATH it inherits, which an SSH-spawned
    # process does not have.
    host = _rundll32_path(info.get("bits"))
    if not Path(host).is_file():
        raise FridaLaunchError(
            f"no rundll32 host for a {info.get('bits')}-bit DLL "
            f"(looked for {host})")
    names = _exports(target)
    entry = forced_entry or _preferred_entry(names)
    if not entry:
        # No provable entry point. Refuse rather than guess silently: a wrong
        # entry point is not the sample.
        raise FridaLaunchError(
            "the target is a DLL with no discernible export to call "
            "(exports: %s). Pass --dll-entry <Name|#ordinal>" %
            (", ".join(names[:6]) or "none found"))
    # rundll32 takes "<file>,<entry>" as ONE argument, and the file first.
    return [host, f"{target},{entry}"], "rundll32", entry


# Entry points malware DLLs conventionally expose. Order matters: a
# registration hook runs before anything else, so it is preferred.
_PREFERRED_ENTRIES = (
    "DllRegisterServer", "DllInstall", "ServiceMain", "DllMain",
    "Go", "Run", "Start", "Main", "Load", "Init", "Install",
)


def _preferred_entry(names: list[str]) -> str | None:
    """The entry point to call. Exact matches on the preferred list first, then
    case-insensitive, then the FIRST export we can prove exists.

    Reversing: b105's PDB told us it exports "Go", and rundll32 with no
    argument at all pops a dialog - a detonation that waits for input is not a
    detonation.
    """
    for want in _PREFERRED_ENTRIES:
        for n in names:
            if n == want:
                return n
    for want in _PREFERRED_ENTRIES:
        for n in names:
            if n.lower() == want.lower():
                return n
    return names[0] if names else None


class FridaLaunchError(RuntimeError):
    """The sample cannot be launched with the information we have."""


def _path_key(path):
    """Normalize Windows paths independent of the host running this helper."""
    if not isinstance(path, str) or not path.strip():
        return ""
    value = path.strip().strip('"').replace("/", "\\").casefold()
    for prefix in ("\\\\?\\", "\\??\\"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value.rstrip("\\")


def gate_for(api, kinds, apis, args=None, path=None, *, sample_path=None):
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
        # The analysis runner stages the input at a .exe path inside
        # C:\\samples. Self-open/self-rewrite operations on that exact input
        # are not a dropped payload and must not arm the early-stop gate.
        if sample_path and _path_key(path) == _path_key(sample_path):
            return None
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
    ap.add_argument("--dll-entry", default=None,
                help="entry point to call when --target is a DLL "
                     "(export name, or #<ordinal>). Defaults to the first of "
                     "DllRegisterServer/DllMain/Go/... that the file exports; "
                     "rundll32 hosts it, which is the only way to run a DLL.")
    ap.add_argument(
        "--apis",
        required=True,
        help="comma-separated API names (e.g. CreateFileW,VirtualAlloc)",
    )
    ap.add_argument("--module", default=None, help="unused (compat); hooks resolve globally")
    ap.add_argument("--out", required=True, help="output JSONL file")
    ap.add_argument("--max-calls", type=int, default=10000)
    ap.add_argument("--max-children", type=int, default=16,
                    help="maximum child processes to instrument (0 disables child gating)")
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

    # Allocate a deterministic per-process slice so the sum across the root
    # plus every allowed child cannot exceed the advertised trace call cap.
    # Unused child allocations remain unused; we never overstate the bound.
    process_slots = max(1, max(0, int(args.max_children)) + 1)
    child_call_budget, root_call_remainder = divmod(
        max(0, int(args.max_calls)), process_slots)
    root_call_budget = child_call_budget + root_call_remainder
    max_calls_total = root_call_budget + child_call_budget * (process_slots - 1)

    apis_js = ",\n        ".join(f'"{a}"' for a in api_list)
    # Path/string decode map: which arg indices are WCHAR* or CHAR*
    # Also sockaddr decoding for connect/sendto when possible.
    js = f"""
'use strict';
const apis = [
        {apis_js}
];
const maxCalls = {root_call_budget};
const maxChildren = {args.max_children};
let callCount = 0;
let invocationSeq = 0;
const hookCoverage = {{requested: apis.slice(), installed: [], installed_exports: [],
    unavailable: [], failures: [], modules_seen: 0, module_observer: 'starting'}};
const attachedExports = {{}};

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
// W1, second half: APIs that WRITE through a handle. With handlePaths
// resolution (P1-F6) their `decoded.path` is an attributed file, so such a call
// is positive write evidence without needing any access mask.
const writeFamilySet = new Set(['WriteFile', 'WriteFileEx', 'WriteFileGather',
  'NtWriteFile', 'FlushFileBuffers', 'fwrite', 'fputs']);
// W1 (RevAI review 2026-10-08): the access bits that make a file open a WRITE.
// These mirror WRITE_ACCESS_BITS on the Python side and gate_for() uses the
// same constants, so the recorded provenance and the gate can never disagree.
const WRITE_ACCESS_MASK = 0x40000000 | 0x00000002 | 0x00000004 | 0x00000100;
const READ_ACCESS_MASK = 0x80000000 | 0x00000001 | 0x00000008 | 0x00000080;
function ptrToU32(p) {{
    try {{ return (p.toUInt32() >>> 0); }} catch (e) {{ return 0; }}
}}
// sockaddr* argument index by API name
const sockaddrArgs = {{
  connect: [1],
  ConnectEx: [1],
  WSAConnect: [1],
  sendto: [4],
  recvfrom: [4],
  WSASendTo: [5],
  WSARecvFrom: [5],
}};
const sockaddrOutputApis = new Set(['recvfrom', 'wsarecvfrom']);
const networkApis = new Set(['connect', 'connectex', 'wsaconnect', 'sendto',
  'recvfrom', 'wsasendto', 'wsarecvfrom', 'winhttpconnect', 'internetconnecta',
  'internetconnectw', 'httpopenrequesta', 'httpopenrequestw', 'winhttpopenrequest',
  'urldownloadtofilea', 'urldownloadtofilew']);

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

function safeReadObjectName(objectAttributes) {{
    try {{
        if (!objectAttributes || objectAttributes.isNull()) return null;
        const nameOffset = Process.pointerSize * 2;
        const name = objectAttributes.add(nameOffset).readPointer();
        if (!name || name.isNull()) return null;
        const bufferOffset = Process.pointerSize === 8 ? 8 : 4;
        const buffer = name.add(bufferOffset).readPointer();
        return safeReadUtf16(buffer);
    }} catch (e) {{ return null; }}
}}

function decodeSockAddr(ptr, length) {{
    try {{
        if (!ptr || ptr.isNull()) return null;
        const family = ptr.readU16();
        if (family === 2) {{ // AF_INET
            if (length !== undefined && length !== null && length < 16) return null;
            const port = ((ptr.add(2).readU8() << 8) | ptr.add(3).readU8());
            const a = ptr.add(4).readU8();
            const b = ptr.add(5).readU8();
            const c = ptr.add(6).readU8();
            const d = ptr.add(7).readU8();
            const ip = a + '.' + b + '.' + c + '.' + d;
            return {{family: 'ipv4', family_number: family, ip: ip, port: port,
                    scope_id: null, endpoint: ip + ':' + port}};
        }}
        if (family === 23) {{ // AF_INET6
            if (length !== undefined && length !== null && length < 28) return null;
            const port = ((ptr.add(2).readU8() << 8) | ptr.add(3).readU8());
            const bytes = new Uint8Array(ptr.add(8).readByteArray(16));
            const groups = [];
            for (let i = 0; i < 16; i += 2)
                groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
            const scope = ptr.add(24).readU32();
            const ip = groups.join(':');
            return {{family: 'ipv6', family_number: family, ip: ip, port: port,
                    scope_id: scope || null,
                    endpoint: '[' + ip + (scope ? '%' + scope : '') + ']:' + port}};
        }}
        return {{family: 'unknown', family_number: family, ip: null,
                port: null, scope_id: null, endpoint: 'family=' + family}};
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
    if (name === 'NtCreateFile' || name === 'ZwCreateFile') {{
        const objectName = safeReadObjectName(args[2]);
        if (objectName !== null) decoded['path'] = objectName;
    }}
    const saIdx = sockaddrArgs[name] || [];
    for (const i of saIdx) {{
        if (sockaddrOutputApis.has(name.toLowerCase())) continue;
        const sa = decodeSockAddr(args[i]);
        if (sa) {{
            decoded['sockaddr' + i] = sa.endpoint;
            decoded['sockaddr_meta' + i] = sa;
        }}
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
    // W1 (RevAI review 2026-10-08): RECORD the access mask for Create*-style
    // calls. The gate below already refuses to claim a drop without write
    // bits, but that decision was thrown away at the summary layer, so
    // findings.py saw a flat list of paths and had to treat every open as a
    // write. A single CreateFileW(..., GENERIC_READ) on a file in the
    // analyst's own Downloads then became `drop:` and a malicious/high verdict.
    // Provenance has to survive into the evidence, not just into the gate.
    if (createApiSet.has(name) && args[1]) {{
        const acc = ptrToU32(args[1]);
        decoded['access'] = '0x' + acc.toString(16);
        decoded['writes'] = !!(acc & WRITE_ACCESS_MASK);
        decoded['write_intent'] = decoded['writes'];
        decoded['reads'] = !!(acc & READ_ACCESS_MASK);
        decoded['provenance'] = 'access-mask';
    }}
    if (createApiSet.has(name)) {{
        const dispositionIdx = (name === 'NtCreateFile' || name === 'ZwCreateFile') ? 7 : 4;
        decoded['creation_disposition'] = ptrToU32(args[dispositionIdx]);
    }}
    // W1, second half: a WRITE-FAMILY call with an attributed path is positive
    // write evidence in its own right, independent of any access mask.
    //
    // Without this, the strict "require write provenance" rule would DISCARD
    // real drops: a sample that opens a handle (sometimes before Frida attaches,
    // so the CreateFile is never observed) and then writes through it is every
    // bit a drop, and 683 real WriteFile events across the packs on disk carry
    // an attributable path. Getting this wrong in the strict direction loses the
    // very evidence the fix was supposed to protect.
    //
    // handlePaths is resolved by the tracer (P1-F6), so `decoded.path` being
    // present means the write is attributed to a specific file. A write-family
    // call against a read-only handle would fail at the API, so the call itself
    // is the evidence.
    if (writeFamilySet.has(name) && decoded['path']) {{
        decoded['writes'] = true;
        decoded['write_intent'] = true;
        decoded['provenance'] = 'write-to-attributed-path';
    }}
    return {{ args: out, decoded: decoded }};
}}

// handle -> path, filled when a CreateFile* returns and cleared on
// CloseHandle so the map cannot grow unbounded across a long window.
const handlePaths = {{}};

function rememberOpenedHandle(name, retval, ctx, outcome) {{
    if (!createApiSet.has(name)) return;
    // Do not bind a stale output handle after a failed NT call, nor a handle
    // whose asynchronous create has not completed yet.
    if (!outcome || outcome.success !== true
        || outcome.effect === 'async_pending_completion_unobserved') return;
    if (retval === null || retval === undefined) return;
    let handle = retval;
    if (name === 'NtCreateFile' || name === 'ZwCreateFile') {{
        try {{ handle = ctx.fileHandlePtr.readPointer(); }} catch (e) {{ return; }}
    }}
    const rv = handle.toString();
    if (rv === '0x0' || rv === '0xffffffff' || rv === '0xffffffffffffffff' || rv === '-1') return;
    if (ctx.filePath) handlePaths[rv] = ctx.filePath;
}}

function forgetHandle(name, args) {{
    if (!closeApiSet.has(name) || !args || !args[0]) return;
    delete handlePaths[args[0].toString()];
}}

function readWrittenBytes(ptr) {{
    try {{
        if (!ptr || ptr.isNull()) return null;
        const value = Process.pointerSize === 8 ? ptr.readU64() : ptr.readU32();
        return Number(value.toString());
    }} catch (e) {{ return null; }}
}}

function returnOutcome(name, retval, ctx) {{
    const low = name.toLowerCase();
    let raw = null;
    try {{ raw = retval ? retval.toString() : '0x0'; }} catch (e) {{}}
    let success = null;
    let bytes = null;
    let writeSucceeded = false;
    let effect = 'attempted';
    if (createApiSet.has(name)) {{
        const ntCreate = low === 'ntcreatefile' || low === 'zwcreatefile';
        let status = null;
        if (low === 'ntcreatefile' || low === 'zwcreatefile') {{
            try {{ status = retval.toUInt32(); success = retval.toInt32() >= 0; }} catch (e) {{}}
        }} else {{
            try {{ success = retval.toUInt32() !== 0xffffffff; }} catch (e) {{}}
        }}
        if (ntCreate && status === 0x103) {{
            success = true;
            effect = 'async_pending_completion_unobserved';
        }} else if (success) {{
            effect = 'opened';
            const createDisposition = ntCreate ? [0, 2, 4, 5] : [1, 2, 5];
            if (createDisposition.indexOf(ctx.creationDisposition) !== -1)
                effect = 'created_or_truncated';
            else if ((!ntCreate && ctx.creationDisposition === 4)
                     || (ntCreate && ctx.creationDisposition === 3))
                effect = 'created_if_absent_or_opened';
        }} else if (success === false) {{ effect = 'failed'; }}
    }} else if (low === 'writefile' || low === 'writefilegather') {{
        try {{ success = retval.toInt32() !== 0; }} catch (e) {{}}
        bytes = low === 'writefile' ? readWrittenBytes(ctx.bytesWrittenPtr) : null;
        writeSucceeded = success === true && bytes !== null && bytes > 0;
        if (writeSucceeded) effect = 'written';
        else if (success === false) effect = 'failed';
        else if (success === true) effect = 'accepted_without_byte_count';
    }} else if (low === 'ntwritefile' || low === 'zwwritefile') {{
        let status = null;
        try {{ status = retval.toUInt32(); success = retval.toInt32() >= 0; }} catch (e) {{}}
        if (status === 0x103) {{
            effect = 'async_pending_completion_unobserved';
            success = true;
        }} else {{
            try {{
                if (ctx.ioStatusPtr && !ctx.ioStatusPtr.isNull()) {{
                    bytes = readWrittenBytes(ctx.ioStatusPtr.add(Process.pointerSize));
                }}
            }} catch (e) {{}}
        }}
        writeSucceeded = success === true && bytes !== null && bytes > 0;
        if (writeSucceeded) effect = 'written';
        else if (success === false) effect = 'failed';
        else if (success === true && effect === 'attempted') effect = 'accepted_without_byte_count';
    }} else if (low === 'writefileex') {{
        try {{ success = retval.toInt32() !== 0; }} catch (e) {{}}
        effect = success === true ? 'async_accepted_completion_unobserved' : 'failed';
    }}
    return {{raw: raw, success: success, bytes_written: bytes,
             write_succeeded: writeSucceeded, effect: effect}};
}}

function emitCoverage() {{
    send({{type: 'coverage', pid: Process.id, requested: hookCoverage.requested,
          installed: hookCoverage.installed, installed_exports: hookCoverage.installed_exports,
          unavailable: hookCoverage.unavailable, failures: hookCoverage.failures,
          max_calls: maxCalls, modules_seen: hookCoverage.modules_seen,
          module_observer: hookCoverage.module_observer,
          process_coverage_complete: hookCoverage.module_observer === 'active',
          scope: 'requested exports in this process; child coverage is reported by the host controller'}});
}}

function callerInfo(address) {{
    try {{
        const module = Process.findModuleByAddress(address);
        const sym = DebugSymbol.fromAddress(address);
        return {{address: address.toString(),
                module: module ? module.name : null,
                module_base: module ? module.base.toString() : null,
                module_offset: module ? address.sub(module.base).toString() : null,
                symbol: sym ? sym.toString() : null}};
    }} catch (e) {{ return {{address: address ? address.toString() : null,
                             resolution_error: String(e)}}; }}
}}

function attachApi(name, module) {{
    try {{
        let addr = null;
        try {{ addr = module ? module.findExportByName(name) : resolveExport(name); }} catch (e) {{}}
        if (!addr) {{
            if (!module && hookCoverage.unavailable.indexOf(name) === -1)
                hookCoverage.unavailable.push(name);
            return;
        }}
        const addrKey = addr.toString();
        const already = attachedExports[name] || [];
        if (already.indexOf(addrKey) !== -1) return;
        attachedExports[name] = already.concat([addrKey]);
        Interceptor.attach(addr, {{
            onEnter: function (args) {{
                this.recorded = false;
                if (callCount >= maxCalls) return;
                callCount++;
                const tid = Process.getCurrentThreadId();
                const enriched = enrichArgs(name, args);
                this.recorded = true;
                this.tid = tid;
                this.invocationId = Process.id + ':' + tid + ':' + (++invocationSeq);
                this.decoded = enriched.decoded;
                this.networkCall = networkApis.has(name.toLowerCase());
                this.caller = this.networkCall ? callerInfo(this.returnAddress) : null;
                this.creationDisposition = enriched.decoded['creation_disposition'];
                this.bytesWrittenPtr = name === 'WriteFile' ? args[3] : null;
                this.ioStatusPtr = (name.toLowerCase() === 'ntwritefile' || name.toLowerCase() === 'zwwritefile') ? args[4] : null;
                if (sockaddrOutputApis.has(name.toLowerCase())) {{
                    const lenArg = name.toLowerCase() === 'recvfrom' ? 5 : 6;
                    this.sockaddrOutPtr = args[(sockaddrArgs[name] || [])[0]];
                    this.sockaddrOutLenPtr = args[lenArg];
                }}
                // P1-F6: stash the path a CreateFile* is opening, so the
                // handle it returns can be resolved back to that path.
                this.filePath = enriched.decoded['path'] || enriched.decoded['arg0'] || null;
                this.fileHandlePtr = args[0];
                if (closeApiSet.has(name)) {{
                    forgetHandle(name, args);
                }}
                send({{
                    type: 'call',
                    ts: Date.now(),
                    api: name,
                    pid: Process.id,
                    tid: tid,
                    invocation_id: this.invocationId,
                    caller: this.caller,
                    args: enriched.args,
                    decoded: enriched.decoded
                }});
            }},
            onLeave: function (retval) {{
                if (!this.recorded) return;
                const outcome = returnOutcome(name, retval, this);
                rememberOpenedHandle(name, retval, this, outcome);
                send({{
                    type: 'ret',
                    ts: Date.now(),
                    api: name,
                    pid: Process.id,
                    tid: this.tid,
                    invocation_id: this.invocationId,
                    retval: outcome.raw,
                    success: outcome.success,
                    bytes_written: outcome.bytes_written,
                    write_succeeded: outcome.write_succeeded,
                    effect: outcome.effect
                }});
                if (sockaddrOutputApis.has(name.toLowerCase())) {{
                    try {{
                        const rc = retval.toInt32();
                        const len = this.sockaddrOutLenPtr && !this.sockaddrOutLenPtr.isNull()
                            ? this.sockaddrOutLenPtr.readU32() : null;
                        if (rc !== -1 && this.sockaddrOutPtr) {{
                            const endpoint = decodeSockAddr(this.sockaddrOutPtr, len);
                            if (endpoint) send({{type: 'endpoint', ts: Date.now(),
                                api: name, pid: Process.id, tid: this.tid,
                                invocation_id: this.invocationId, caller: this.caller,
                                decoded_key: 'sockaddr_out', address: endpoint.endpoint,
                                address_family: endpoint.family,
                                family_number: endpoint.family_number,
                                ip: endpoint.ip, port: endpoint.port,
                                scope_id: endpoint.scope_id,
                                role: 'inbound'}});
                        }}
                    }} catch (e) {{}}
                }}
            }}
        }});
        if (hookCoverage.installed.indexOf(name) === -1)
            hookCoverage.installed.push(name);
        hookCoverage.installed_exports.push({{api: name,
            module: module ? module.name : (Process.findModuleByAddress(addr) || {{}}).name || null,
            address: addrKey}});
        hookCoverage.unavailable = hookCoverage.unavailable.filter(x => x !== name);
    }} catch (e) {{
        hookCoverage.failures.push({{api: name, module: module ? module.name : null,
                                     error: String(e)}});
    }}
}}

apis.forEach(name => attachApi(name, null));
try {{
    hookCoverage.module_observer = 'active';
    Process.attachModuleObserver({{
        onAdded(module) {{
            hookCoverage.modules_seen++;
            const before = hookCoverage.installed_exports.length;
            apis.forEach(name => attachApi(name, module));
            if (hookCoverage.installed_exports.length !== before) emitCoverage();
        }}
    }});
}} catch (e) {{
    hookCoverage.module_observer = 'failed';
    hookCoverage.failures.push({{api: '<module-observer>', error: String(e)}});
}}
emitCoverage();
function listenForControl() {{
    recv('coverage-flush', function () {{
        emitCoverage();
        send({{type: 'coverage-flushed', pid: Process.id}});
        listenForControl();
    }});
}}
listenForControl();
send({{type: 'log', level: 'info', msg: 'hooks installed'}});
"""

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    device = frida.get_local_device()
    spawned_pid = None
    launch = {"argv": [], "loader": "direct", "entry": None}

    if args.pid:
        print(f"attaching to pid={args.pid}", file=sys.stderr)
        session = device.attach(args.pid)
    elif args.target:
        print(f"spawning {args.target}", file=sys.stderr)
        if not Path(args.target).is_file():
            print(f"FATAL: target not found: {args.target}", file=sys.stderr)
            sys.exit(1)
        # A DLL cannot be spawned: Frida's device.spawn only accepts
        # executables, and it says so verbatim - "unsupported file format".
        # b105 (2026-10-06) died there and the whole detonation vanished while
        # the stage still reported green. An analyst loads a DLL through a
        # host, so that is what we do: rundll32.exe <dll>,<EntryPoint>.
        argv, loader, entry = _launch_argv(args.target, args.dll_entry)
        launch = {"argv": argv, "loader": loader, "entry": entry}
        print(f"loader={loader} entry={entry}", file=sys.stderr)
        spawned_pid = device.spawn(argv)
        # The job tracks this run by PROCESS NAME, which is rundll32 when we
        # host a DLL - and a name match finds nothing when several rundll32s
        # are alive. Report the real pid so the job can use it verbatim.
        print(f"spawned_pid={spawned_pid}", file=sys.stderr)
        session = device.attach(spawned_pid)
    else:
        print("FATAL: must specify --target or --pid", file=sys.stderr)
        sys.exit(1)

    script = session.create_script(js)
    out_fh = open(out_path, "w", encoding="utf-8")
    write_lock = threading.Lock()
    closed = {"done": False}
    child_lock = threading.RLock()
    child_scripts = []
    child_sessions = []
    instrumented_pids = {int(spawned_pid or args.pid)}
    coverage_by_pid = {}
    coverage_flush_acks = set()
    child_state = {"requested": max(0, int(args.max_children)) > 0,
                   "enabled": False, "attempted": 0,
                   "instrumented": [], "failures": [], "limit_reached": False,
                   "inflight": 0, "enable_error": None,
                   "signal_registered": False}
    call_counts = {}
    # shared, mutable time origin: the message handler can fire as soon as the
    # script loads, before the run loop assigns its own t_start
    t0 = {"t": time.time()}
    last = {"t": t0["t"]}
    gate_kinds, gate_apis = parse_stop_on(getattr(args, "stop_on", ""))
    gate_settle = max(0, int(getattr(args, "stop_on_settle", 20) or 0))
    gate = {"fired": False, "at_s": None, "kind": None, "api": None,
            "stop_at": None, "path": None, "arg0": None,
            "invocation_id": None}

    def on_message(msg, data):
        if closed["done"]:
            return
        try:
            if msg["type"] == "send":
                payload = msg.get("payload") or {}
                if isinstance(payload, dict):
                    if payload.get("type") == "coverage":
                        coverage_by_pid[str(payload.get("pid"))] = payload
                    elif payload.get("type") == "coverage-flushed":
                        coverage_flush_acks.add(str(payload.get("pid")))
                    elif payload.get("type") == "call":
                        key = str(payload.get("pid"))
                        call_counts[key] = call_counts.get(key, 0) + 1
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
                    if isinstance(payload, dict) and payload.get("type") == "call":
                        hit = gate_for(payload.get("api"), gate_kinds,
                                       gate_apis, payload.get("args"),
                                       path=(payload.get("decoded") or {}).get("path")
                                            or (payload.get("decoded") or {}).get("arg0"),
                                       sample_path=getattr(args, "target", None))
                        if hit:
                            now = time.time()
                            _dec = payload.get("decoded") or {}
                            gate.update({
                                "fired": True, "kind": hit,
                                "api": payload.get("api"),
                                "invocation_id": payload.get("invocation_id"),
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

    def _write_controller_event(payload):
        try:
            with write_lock:
                if not closed["done"]:
                    out_fh.write(json.dumps(payload) + "\n")
                    out_fh.flush()
        except Exception:
            pass

    def _instrument_child(child):
        pid = int(getattr(child, "pid", 0) or 0)
        record = {"type": "process", "action": "child_instrumentation",
                  "ts": time.time(), "pid": pid,
                  "parent_pid": getattr(child, "parent_pid", None),
                  "path": getattr(child, "path", None),
                  "argv": getattr(child, "argv", None)}
        try:
            child_session = device.attach(pid)
            child_session.enable_child_gating()
            # Root source uses its allocated share; each child receives the
            # fixed child slice from the same aggregate budget.
            child_js = js.replace(
                f"const maxCalls = {root_call_budget};",
                f"const maxCalls = {child_call_budget};")
            child_script = child_session.create_script(child_js)
            child_script.on("message", on_message)
            child_script.load()
            with child_lock:
                child_sessions.append(child_session)
                child_scripts.append(child_script)
                instrumented_pids.add(pid)
                child_state["instrumented"].append(pid)
            record.update(status="instrumented", max_calls=child_call_budget)
            device.resume(pid)
        except Exception as e:
            record.update(status="failed", error=f"{type(e).__name__}: {str(e)[:220]}")
            with child_lock:
                child_state["failures"].append({"pid": pid, "error": record["error"]})
            # A failed callback must not strand a child in a suspended state.
            try:
                device.resume(pid)
            except Exception as resume_error:
                record["resume_error"] = f"{type(resume_error).__name__}: {str(resume_error)[:100]}"
        _write_controller_event(record)
        with child_lock:
            child_state["inflight"] = max(0, child_state["inflight"] - 1)

    def _on_child_added(_device, child):
        pid = int(getattr(child, "pid", 0) or 0)
        with child_lock:
            if pid in instrumented_pids:
                return
            child_state["attempted"] += 1
            accepted = child_state["attempted"] <= max(0, int(args.max_children))
            if not accepted:
                child_state["limit_reached"] = True
                record = {"type": "process", "action": "child_instrumentation",
                          "ts": time.time(), "pid": pid,
                          "parent_pid": getattr(child, "parent_pid", None),
                          "path": getattr(child, "path", None),
                          "status": "not_instrumented",
                          "reason": "max_children limit reached"}
                child_state["failures"].append({"pid": pid,
                                                "error": record["reason"]})
                _write_controller_event(record)
                try:
                    device.resume(pid)
                except Exception:
                    pass
                return
            instrumented_pids.add(pid)  # reserve before starting the worker
            child_state["inflight"] += 1
        threading.Thread(target=_instrument_child, args=(child,), daemon=True).start()

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

    try:
        device.on("child-added", _on_child_added)
        child_state["signal_registered"] = True
    except Exception as e:
        child_state["failures"].append({"error": f"child-added signal unavailable: {str(e)[:160]}"})
    if child_state["requested"]:
        try:
            session.enable_child_gating()
            child_state["enabled"] = True
        except Exception as e:
            child_state["enable_error"] = f"{type(e).__name__}: {str(e)[:180]}"
            child_state["failures"].append({"error": child_state["enable_error"]})

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
    detached_gate_waiting = False
    try:
        while (time.time() < deadline
               or gate_settle_pending(gate, time.time())):
            time.sleep(0.5)
            try:
                if session.is_detached:
                    with child_lock:
                        active_children = []
                        for child_session in child_sessions:
                            try:
                                if not child_session.is_detached:
                                    active_children.append(child_session)
                            except Exception:
                                pass
                        child_pending = child_state["inflight"] > 0
                    if not active_children and not child_pending:
                        settle_pending = gate_settle_pending(gate, time.time())
                        if settle_pending:
                            # Process exit does not cancel the observation
                            # window opened by a behavior gate. Procmon and
                            # network capture continue collecting independently
                            # of the Frida target until the configured settle
                            # deadline, so preserve that interval here too.
                            if not detached_gate_waiting:
                                print(
                                    "instrumented process tree detached; "
                                    f"preserving gate settle for {gate_settle}s",
                                    file=sys.stderr,
                                )
                                detached_gate_waiting = True
                        elif not gate["fired"]:
                            stop_reason = "detached"
                            print("instrumented process tree detached", file=sys.stderr)
                            break
            except Exception:
                # Frida may raise while the target is detaching. A fired gate
                # still owns its settle interval even when session state can
                # no longer be queried.
                settle_pending = gate_settle_pending(gate, time.time())
                if not settle_pending:
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
                if gate_settle_pending(gate, time.time()):
                    # Idle-stop is a cap for a no-gate run. Once a behaviour
                    # gate fires, preserve its full settle window so follow-on
                    # traffic and side effects are not cut off early.
                    continue
                stop_reason = "idle"
                print(f"idle-stop: no events for {idle_stop}s", file=sys.stderr)
                break
    except KeyboardInterrupt:
        stop_reason = "interrupted"
        print("interrupted; detaching", file=sys.stderr)
    with child_lock:
        scripts_to_flush = [script] + list(child_scripts)
    for active_script in scripts_to_flush:
        try:
            active_script.post({"type": "coverage-flush"})
        except Exception:
            pass
    flush_deadline = time.time() + 3.0
    expected_flush_pids = {str(int(spawned_pid or args.pid))} | {
        str(pid) for pid in child_state["instrumented"]}
    while ((child_state["inflight"] or
            not expected_flush_pids.issubset(coverage_flush_acks))
           and time.time() < flush_deadline):
        time.sleep(0.05)
    process_ids = sorted({int(spawned_pid or args.pid)} |
                         set(child_state["instrumented"]))
    module_coverage_complete = all(
        coverage_by_pid.get(str(pid), {}).get("module_observer") == "active"
        and str(pid) in coverage_flush_acks for pid in process_ids)
    process_tree_complete = bool(
        spawned_pid is not None and child_state["enabled"]
        and child_state["signal_registered"] and module_coverage_complete
        and not child_state["failures"] and not child_state["limit_reached"]
        and child_state["inflight"] == 0)
    process_tree = {
        "type": "coverage_tree", "ts": time.time(),
        "root_pid": int(spawned_pid or args.pid),
        "max_calls_total": max_calls_total,
        "root_call_budget": root_call_budget,
        "child_call_budget": child_call_budget,
        "root_mode": "spawned" if spawned_pid is not None else "attached",
        "child_gating_requested": child_state["requested"],
        "child_gating_enabled": child_state["enabled"],
        "child_added_signal_registered": child_state["signal_registered"],
        "child_gating_error": child_state["enable_error"],
        "children_seen": child_state["attempted"],
        "children_instrumented": sorted(child_state["instrumented"]),
        "instrumented_pids": process_ids,
        "child_failures": child_state["failures"],
        "child_limit_reached": child_state["limit_reached"],
        "module_observers_complete": module_coverage_complete,
        "process_coverage_complete": process_tree_complete,
        "calls_by_pid": call_counts,
        "limitations": (["attached to an already-running root; child creation before gating may be missed"]
                        if spawned_pid is None else []) +
                       (["one or more child processes were not instrumented"]
                        if child_state["failures"] else []) +
                       (["not all process module observers reported active"]
                        if not module_coverage_complete else []),
    }
    _write_controller_event(process_tree)
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
                       "gate_path": gate["path"],
                       "gate_arg0": gate["arg0"],
                       "gate_invocation_id": gate["invocation_id"],
                       "gate_at_s": gate["at_s"],
                       "process_tree": process_tree}, fh)
    except Exception:
        pass

    closed["done"] = True
    if spawned_pid is not None:
        try:
            device.kill(spawned_pid)
        except Exception:
            pass
    for active_script in scripts_to_flush:
        try:
            active_script.unload()
        except Exception:
            pass
    for child_session in child_sessions:
        try:
            child_session.disable_child_gating()
            child_session.detach()
        except Exception:
            pass
    try:
        session.disable_child_gating()
    except Exception:
        pass
    try:
        device.off("child-added", _on_child_added)
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
