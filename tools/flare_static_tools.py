#!/usr/bin/env python3
"""flare_static_tools.py — RevAI-parity static evidence wrappers (Windows).

Each wrapper runs one static-analysis tool on the FlareVM and prints a
compact JSON result. All tolerate absence (tool not installed -> {"ok":
False, "skipped": ...}) so the free-tools path degrades gracefully.

Tools (all FREE):
  capa     - flare-capa + mandiant rules (C:\\Tools\\capa-rules)  [pip]
  floss    - FLARE obfuscated-string extractor                   [pip]
  lief     - PE parse: imports/sections/signatures/entry         [pip]
  diec     - Detect It Easy: packer/compiler ID (C:\\Tools\\die)  [binary]
  ilspy    - .NET assembly decompile (dotnet tool)               [dotnet tool]
  yarascan - yara-x (yr) scan against staged rules dir           [binary]
  strings  - ASCII/unicode strings (Sysinternals strings64)      [binary]
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

PY = sys.executable or r"C:\Python313\python.exe"
CAPA_RULES = r"C:\Tools\capa-rules"
DIE_DIR = r"C:\Tools\die"
ILSPY = str(Path.home() / ".dotnet" / "tools" / "ilspycmd.exe")
YARA_RULES_DIR = r"C:\Tools\yara-rules"
STRINGS64 = r"C:\Tools\sysinternals\strings64.exe"


def _run(cmd: list[str], timeout: int, env: dict | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace", env=env)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"not found: {e}"


def _skipped(tool: str, detail: str = "") -> dict:
    return {"ok": False, "skipped": f"{tool}: {detail or 'not available'}"}


def capa(sample: str, timeout: int = 900) -> dict:
    """capa — standalone exe preferred (embeds function-ID sigs); pip capa
    needs a site-packages\\sigs dir that doesn't ship separately."""
    exe = Path(r"C:\Tools\capa\capa.exe")
    rules = Path(CAPA_RULES)
    if not any(rules.rglob("*.yml")):
        return _skipped("capa-rules", "no rules under C:\\Tools\\capa-rules")
    if exe.is_file():
        cmd = [str(exe), sample, "-r", CAPA_RULES, "--json", "-q"]
    else:
        import importlib.util
        if importlib.util.find_spec("capa") is None:
            return _skipped("capa", "no exe and no pip module")
        cmd = [PY, "-c",
               "import sys; sys.argv=['capa', sys.argv[1], '-r', sys.argv[2], "
               "'--json', '-q']; from capa.main import main; main()",
               sample, CAPA_RULES]
    rc, out, err = _run(cmd, timeout)
    if rc != 0:
        return {"ok": False, "error": (err or out)[-300:], "tool": "capa"}
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return {"ok": False, "error": "capa non-JSON output", "tool": "capa"}
    rules_hits = []
    for rule_name, rule in (d.get("rules") or {}).items():
        meta = rule.get("meta") or {}
        if meta.get("lib"):
            continue  # skip library rules
        attacks = [f"{a.get('tactic')}:{a.get('technique')}"
                   for a in (meta.get("attack") or [])]
        rules_hits.append({"name": rule_name,
                           "mastrust": meta.get("mastrust"),
                           "attack": attacks,
                           "count": len(rule.get("matches") or {})})
    return {"ok": True, "tool": "capa",
            "capabilities": rules_hits, "total": len(rules_hits)}


def floss(sample: str, timeout: int = 900) -> dict:
    import importlib.util
    if importlib.util.find_spec("floss") is None:
        return _skipped("floss")
    # pip floss entry: floss.main lacks __main__ on some builds — use the
    # documented API entry (floss.main.main) with explicit argv, else Scripts exe
    exe = Path(PY).parent / "Scripts" / "floss.exe"
    roaming = Path.home() / "AppData" / "Roaming" / "Python" / "Python313" / "Scripts" / "floss.exe"
    if exe.is_file():
        cmd = [str(exe), sample, "--json"]
    elif roaming.is_file():
        cmd = [str(roaming), sample, "--json"]
    else:
        cmd = [PY, "-c",
               "import sys; sys.argv=['floss', sys.argv[1], '--json']; "
               "from floss.main import main; exit(main())",
               sample]
    rc, out, err = _run(cmd, timeout)
    if rc != 0:
        return {"ok": False, "error": (err or out)[-300:], "tool": "floss"}
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return {"ok": False, "error": "floss non-JSON output", "tool": "floss"}
    strings = []
    for feat in (d.get("strings") or {}).get("decoded_strings", []):
        s = feat.get("string", "")
        if 6 <= len(s) <= 200:
            strings.append(s)
    # dedupe, cap at 60 for evidence size
    uniq = list(dict.fromkeys(strings))[:60]
    return {"ok": True, "tool": "floss", "decoded_strings": uniq,
            "total_decoded": len(strings)}


def lief_parse(sample: str, timeout: int = 300) -> dict:
    """PE parse via pefile (primary — pure-python, crash-proof).

    lief is avoided here: its C++ parse hard-crashes on some packed/corrupt
    PEs, taking the whole evidence call with it. lief stays installed for
    future programmatic use, but evidence comes from pefile.
    """
    import importlib.util
    if importlib.util.find_spec("pefile") is None:
        return _skipped("pefile")
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                         pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
        imports = []
        for imp in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []):
            fns = [(getattr(e, "name", b"") or b"").decode("ascii", "replace")
                   for e in (imp.imports or [])]
            imports.append({"dll": imp.dll.decode("ascii", "replace"),
                            "functions": fns[:40]})
        sections = [{"name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                     "size": s.Misc_VirtualSize,
                     "entropy": round(s.get_entropy(), 2)} for s in pe.sections]
        has_sig = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress)
        info = {}
        try:
            for fi in (pe.FileInfo or []):
                for entry in fi:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            info = {k.decode(): v.decode()
                                    for k, v in (st.entries or {}).items()}
        except Exception:
            pass
        return {"ok": True, "tool": "pefile",
                "machine": hex(pe.FILE_HEADER.Machine),
                "entrypoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "imports": imports,
                "sections": sections,
                "signed": has_sig,
                "version_info": info,
                "compile_ts": pe.FILE_HEADER.TimeDateStamp}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "tool": "pefile"}


def diec(sample: str, timeout: int = 300) -> dict:
    exe = Path(DIE_DIR) / "diec.exe"
    if not exe.is_file():
        return _skipped("diec", "C:\\Tools\\die\\diec.exe missing")
    rc, out, err = _run([str(exe), "-j", sample], timeout)
    if rc != 0:
        return {"ok": False, "error": (err or out)[-200:], "tool": "diec"}
    # diec prints a stderr-style banner ("[!] Heuristic scan...") before the
    # JSON — start parsing at the first balanced object
    start = (out or "").find("{")
    if start < 0:
        return {"ok": False, "error": "diec non-JSON", "tool": "diec"}
    try:
        d = json.loads(out[start:])
        detects = (d.get("detects") or [])
        names = [x.get("name") for x in detects if x.get("name")][:10]
        return {"ok": True, "tool": "diec", "detects": names}
    except json.JSONDecodeError:
        return {"ok": False, "error": "diec non-JSON", "tool": "diec"}


def ilspy(sample: str, timeout: int = 600) -> dict:
    exe = Path(ILSPY)
    if not exe.is_file():
        return _skipped("ilspycmd", "dotnet tool not installed")
    rc, out, err = _run([str(exe), sample, "-lc", "20"], timeout)
    if rc != 0:
        return {"ok": False, "error": (err or out)[-200:], "tool": "ilspy"}
    text = out
    return {"ok": True, "tool": "ilspy", "decompiled_head": text[:4000],
            "length": len(text)}


# ── YARA hit specificity ─────────────────────────────────────────────────────
# Auto-generated rules (yara_gen_v2-style) often use conditions like
# `uint16(0) == 0x5A4D and 2 of them or pe.imphash() == ...` over generic
# strings (DOS stub, KERNEL32.DLL, ExitProcess, ...) — which fire on almost
# every Windows PE (benign notepad matched 4 malware-family rules). Only a
# FAMILY-DISTINCTIVE matched pattern may drive verdicts; generic matches stay
# as evidence but are non-decisive.
_YARA_GENERIC_LITERALS = {
    "this program cannot be run in dos mode",
    "!this program cannot be run in dos mode.",
    "mz", "pe", "rich", ".text", ".data", ".rdata", ".rsrc", ".reloc",
    "software\\microsoft", "microsoft corporation", "microsoft windows",
    "software", "software\\", "oftware", "oftware\\", "microsoft",
    "unknown exception", "bad allocation", "out of memory",
    "invalid parameter", "assertion failed", "abnormal program termination",
    # CRT / ATL boilerplate (family rules generated from MSVC apps pull these)
    "unable to initialize critical section",
    "catlbasemodule", "catlexception", "atlthrow", "atlbase", "atlcom",
    "atlwin", "pure virtual function call", "vector too long",
    "string too long", "ios_base::badbit set",
    "microsoft visual c++ runtime library", "runtime error!",
    "invalid parameter passed to c runtime function",
    "this application has requested the runtime to terminate it in an unusual way.",
    "terminate called after throwing an instance of",
    "corexitprocess", "corbindtoruntimeex", "corbindtoruntime",
    "corruntimehost", "clrexception",
    "isolationaware function called after isolationawarecleanup",
}
_YARA_GENERIC_PREFIXES = (
    "<?xml", "<assembly", "<dependency", "<dependentassembly", "<trustinfo",
    "<compatibility", "<requestedexecutionlevel", "<description",
    "version=", "type=", "manifestversion=",
    "software\\microsoft", "error : ", "error: ", "unable to ",
    "invalid parameter passed to ", "isolationaware ",
    # Windows component paths / registry hives (universal, not family-level)
    "\\internet explorer", "hardware\\", "system\\currentcontrolset",
    "software\\",
    # XML/manifest attribute assignments (every modern PE manifest has them)
    'name=\\"', 'id=\\"', 'classid=\\"', 'progid=\\"', 'path=\\"',
    'file=\\"', 'key=\\"',
)
# DLL checks are STEM-based: bare or wide forms ("advapi32", "ADVAPI32") must
# classify like "advapi32.dll" — matching only full names let them slip.
_YARA_GENERIC_DLL_STEMS = {
    "kernel32", "user32", "advapi32", "shell32", "ole32", "oleaut32",
    "ntdll", "msvcrt", "gdi32", "ws2_32", "wininet", "urlmon", "winhttp",
    "psapi", "shlwapi", "comctl32", "comdlg32", "version", "crypt32",
    "bcrypt", "sechost", "rpcrt4", "ucrtbase", "vcruntime140", "msvcp140",
    "imm32", "mpr", "netapi32", "wtsapi32", "dnsapi", "iphlpapi", "win32u",
}
# CamelCase WinAPI-shaped identifiers (verb + noun) are behavioral, not
# family-level evidence. Family markers (mutexes, config keys, tags) rarely
# look like API calls.
_YARA_API_SHAPE = re.compile(
    r"^(?:Nt|Zw|Rtl|WSA|Get|Set|Create|Open|Close|Read|Write|Load|Free|Alloc|"
    r"Virtual|Heap|File|Find|Enum|Reg|Query|Delete|Remove|Initialize|"
    r"Uninitialize|Is|Has|Can|Wait|Sleep|Exit|Terminate|Start|Stop|Send|Recv|"
    r"Receive|Connect|Socket|Execute|Shell|Register|Unregister|Crypt|BCrypt|"
    r"Adjust|Change|Move|Copy|Compare|Convert|Format|Message|Dialog|Show|"
    r"Update|Draw|Paint|Peek|Translate|Dispatch|End|Begin|Destroy|Replace|"
    r"Enable|Disable|Insert|Append|Cancel|Release|Reset|Select|Parse|Print|"
    r"Refresh|Validate|Verify|Call|Commit|Flush|Map|Unmap|Track|Expand|"
    r"Interlocked|Try|Acquire|Unlock|Exchange|Increment|Decrement|Signal|"
    r"Setup|Teardown|Resolve|Suspend|Resume|Restore|Save|Submit|Encode|"
    r"Decode|Duplicate|Attach|Detach|Notify|Kill|Pt|Reply|Post|Enqueue|"
    r"Dequeue|Def|Broadcast)[A-Za-z0-9_]{0,30}$")
_YARA_SECTION_RE = re.compile(r"^\.[a-z0-9_$]+$", re.IGNORECASE)
_YARA_HEX_ESC_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _is_generic_dll(low: str) -> bool:
    """Bare, suffixed, or path-prefixed DLL names — stem match.

    "advapi32", "ADVAPI32.dll", "System32\\advapi32.dll" all classify.
    """
    tail = low.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    for cand in (low, tail):
        stem = cand.removesuffix(".dll").removesuffix(".lib")
        if stem in _YARA_GENERIC_DLL_STEMS:
            return True
    return False


def _generic_literal(text: str) -> bool:
    """True when a matched YARA pattern is non-distinctive (common noise).

    yara-x escapes matched bytes as literal \\xNN in JSON — unescape first so
    wide API names and header bytes classify correctly.
    """
    s = _YARA_HEX_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), text or "")
    s = s.replace("\\\\", "\\")  # yara-x escapes backslash once, JSON again
    s = s.replace("\x00", "").strip()
    if not s:
        return True
    low = s.lower()
    if low in _YARA_GENERIC_LITERALS or _is_generic_dll(low):
        return True
    if s.startswith("?"):
        return True  # MSVC C++ mangled symbol (?Fn@@YAXH@Z, ?AVCAtlException@@)
    if low.startswith(_YARA_GENERIC_PREFIXES):
        return True  # XML/manifest boilerplate present in every modern PE
    if low.startswith("mz") or low.startswith("pe") or _YARA_SECTION_RE.match(low):
        return True  # DOS/PE headers, section names (incl. .idata$5 style)
    if re.fullmatch(r"[A-Z]{8,}", s):
        return True  # all-caps opcode soup ("WATAUAVAWH")
    if s.startswith("_") and len(s) >= 8:
        return True  # CRT internals (_register_thread_local_exe_atexit_callback)
    base = low.strip("\\")
    if base in ("software", "oftware", "microsoft"):
        return True
    alnum_runs = re.findall(r"[A-Za-z0-9]{8,}", s)
    if any(ord(ch) < 9 or ord(ch) > 126 for ch in s):
        # raw binary/opcode pattern: specific only with a printable payload
        return not alnum_runs
    longest = max((len(r) for r in re.findall(r"[A-Za-z0-9]+", s)), default=0)
    if longest < 7 and len(s) < 24:
        return True  # symbol soup / compiler opcode bytes ("L$ SUVWH")
    if not re.search(r"[a-z]", s) and re.search(r"[\$^\]@]", s):
        return True  # uppercase opcode soup with symbols ("\\$ UVWAVAWH", "@WATAUAVAWH")
    if len(s) < 20 and re.search(r"[A-Z]{5,}", s) and re.search(r"[a-z]", s):
        return True  # opcode run + stray lowercase ("x ATAUAVH")
    if _YARA_API_SHAPE.match(s) and len(s) < 48:
        return True  # CamelCase WinAPI-shaped identifier
    return False


def _specific_match(matches: list[str]) -> bool:
    """At least one matched pattern is family-distinctive."""
    return any(not _generic_literal(m) for m in matches)


def yarascan(sample: str, timeout: int = 600) -> dict:
    yr = None
    for cand in (r"C:\Tools\yr\yr.exe", "yr"):
        try:
            p = subprocess.run([cand if cand != "yr" else "yr", "--version"],
                               capture_output=True, text=True, timeout=15)
            yr = cand if p.returncode == 0 else yr
            if yr:
                break
        except FileNotFoundError:
            continue
    if not yr:
        return _skipped("yara-x")
    rules_dir = Path(YARA_RULES_DIR)
    yar_files = sorted(f for f in (rules_dir.glob("*.yar") if rules_dir.is_dir() else [])
                       if not f.name.startswith("_bundle"))
    if not yar_files:
        return {"ok": True, "tool": "yarascan", "hits": [],
                "skipped": "no rules staged in C:\\Tools\\yara-rules (operator adds curated sets)"}
    # Scan per-file: one bad rule must never kill the whole batch.
    # JSON + matched patterns: classify each match as high-signal
    # (family-distinctive) or generic (common API/DLL/DOS-stub noise).
    hits: list[str] = []
    high: list[str] = []
    generic: list[str] = []
    detail: dict = {}
    bad = 0
    for rf in yar_files:
        rc, out, err = _run([yr, "scan", "-o", "json", "-s=120",
                             str(rf), sample], min(120, timeout))
        if rc != 0:
            bad += 1
            continue
        parsed = None
        try:
            parsed = json.loads(out or "")
        except Exception:
            parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get("matches"), list):
            for m in parsed["matches"]:
                if not isinstance(m, dict):
                    continue
                rule = str(m.get("rule") or "").strip()
                if not rule or rule in hits:
                    continue
                hits.append(f"{rule} {sample}")
                matched = [str(s.get("match") or "")
                           for s in (m.get("strings") or [])
                           if isinstance(s, dict)]
                if matched:
                    detail[rule] = [t[:60] for t in matched[:4]]
                if not matched or _specific_match(matched):
                    high.append(rule)   # no printed strings (hex/imphash/pe) = specific
                else:
                    generic.append(rule)
                if len(hits) >= 40:
                    break
        else:
            # text fallback (older yr builds) — names only, treated as
            # evidence-only until specificity can be classified
            for line in (out or "").splitlines():
                line = line.strip()
                if line and line not in hits:
                    hits.append(line)
                    generic.append(line.split()[0])
                if len(hits) >= 40:
                    break
        if len(hits) >= 40:
            break
    return {"ok": True, "tool": "yarascan", "hits": hits[:40],
            "high_signal": high[:40], "generic": generic[:40],
            "match_detail": detail,
            "total": len(hits), "rules_scanned": len(yar_files),
            "rules_failed": bad}


def strings(sample: str, timeout: int = 300) -> dict:
    exe = Path(STRINGS64)
    if not exe.is_file():
        return _skipped("strings64")
    rc, out, err = _run([str(exe), "-accepteula", "-nobanner", "-n", "8", sample],
                        timeout)
    lines = [l.strip() for l in (out or "").splitlines() if l.strip()]
    interesting = [l for l in lines if len(l) >= 8][:80]
    return {"ok": True, "tool": "strings", "total": len(lines),
            "strings": interesting}


# ── Tier A: RevAI-method ports (Windows-native implementations) ────────────

_PE_IMPORT_SIGNALS = (
    ("VirtualAllocEx", "allocate_memory", ["T1055"]),
    ("WriteProcessMemory", "write_process_memory", ["T1055"]),
    ("CreateRemoteThread", "create_remote_thread", ["T1055"]),
    ("NtUnmapViewOfSection", "unmap_section_view", ["T1055"]),
    ("QueueUserAPC", "queue_apc", ["T1055"]),
    ("SetThreadContext", "set_thread_context", ["T1055"]),
    ("IsDebuggerPresent", "check_debugger", ["T1622"]),
    ("CheckRemoteDebuggerPresent", "check_remote_debugger", ["T1622"]),
    ("CryptEncrypt", "crypto_encrypt", ["T1573"]),
    ("BCryptEncrypt", "bcrypt_encrypt", ["T1573"]),
    ("InternetOpen", "http_client", ["T1071.001"]),
    ("WinHttpOpen", "winhttp_client", ["T1071.001"]),
    ("URLDownloadToFile", "download_file", ["T1105"]),
    ("CreateService", "create_service", ["T1543.003"]),
    ("RegSetValue", "set_registry_value", ["T1112"]),
    ("CreateProcess", "create_process", ["T1106"]),
    ("ShellExecute", "shell_execute", ["T1106"]),
    ("LoadLibrary", "load_library", ["T1129"]),
    ("GetProcAddress", "get_proc_address", ["T1129"]),
    ("VirtualProtect", "change_memory_protection", ["T1055"]),
    ("VirtualAlloc", "allocate_memory", ["T1055"]),
)


def pe_import_signals(sample: str, timeout: int = 300) -> dict:
    """PE import table high-signal API map (pefile). NOT capa — never label
    as capa. Verbatim port of RevAI v2_lib.pe_import_signals."""
    t0 = time.time()
    imports_seen: list[str] = []
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in getattr(entry, "imports", []) or []:
                name = (imp.name.decode("utf-8", "ignore") if imp.name else "") or ""
                if name:
                    imports_seen.append(name)
        pe.close()
    except Exception as e:
        return {"ok": False, "error": f"pe_import_signals failed: {e}",
                "engine": "pe_imports", "signal_count": 0, "signals": []}
    lower_keys = [n.lower() for n in imports_seen]
    signals: list[dict] = []
    seen_labels: set[str] = set()
    for api, label, tactics in _PE_IMPORT_SIGNALS:
        if any(api.lower() in k for k in lower_keys):
            if label in seen_labels:
                continue
            seen_labels.add(label)
            signals.append({"label": label, "api_match": api, "attack": tactics})
    return {"ok": True, "tool": "pe_import_signals", "engine": "pe_imports",
            "duration_s": round(time.time() - t0, 2),
            "import_count": len(imports_seen), "signal_count": len(signals),
            "signals": signals,
            "hint": "PE import high-signal map (pefile). Not capa."}


# ── API-hash resolver detection (KB: AMAT Track 8 Miniduke / MalTrak Emotet) ─
# Runtime import resolvers hash API names (murmur2/3, djb2, sdbm, fnv) and
# call GetProcAddress/LdrGetProcedureAddress with the constant — a classic
# evasion/anti-import-table technique. Detection = find 4-byte constants in
# executable sections that equal a known-algorithm hash of a common API name.
# Matched names are evidence AND config/IOC value (they reveal which APIs the
# loader resolves at runtime, which static imports cannot).

_API_HASH_DICT: dict[str, tuple[str, ...]] = {
    "kernel32.dll": ("VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualFree",
                     "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
                     "OpenProcess", "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
                     "CreateProcessA", "CreateProcessW", "GetModuleHandleA",
                     "GetModuleHandleW", "GetModuleFileNameA", "GetModuleFileNameW",
                     "Sleep", "GetTickCount", "GetTickCount64", "GetCurrentProcess",
                     "GetCurrentProcessId", "GetCurrentThreadId", "GetSystemInfo",
                     "GlobalMemoryStatusEx", "GetComputerNameA", "GetComputerNameW",
                     "GetUserNameA", "GetUserNameW", "GetTempPathA", "GetTempPathW",
                     "GetCommandLineA", "GetCommandLineW", "GetEnvironmentVariableA",
                     "GetEnvironmentVariableW", "SetEnvironmentVariableA", "CreateMutexA",
                     "CreateMutexW", "CreateThread", "ExitProcess", "TerminateProcess",
                     "CloseHandle", "DeleteFileA", "DeleteFileW", "CopyFileA",
                     "CopyFileW", "MoveFileA", "MoveFileW", "CreateDirectoryA",
                     "CreateDirectoryW", "RemoveDirectoryA", "RemoveDirectoryW",
                     "FindFirstFileA", "FindFirstFileW", "FindNextFileA",
                     "FindNextFileW", "GetFileAttributesA", "GetFileAttributesW",
                     "SetFileAttributesA", "SetFileAttributesW", "GetFileSize",
                     "GetFileSizeEx", "SetFilePointer", "ReadFile", "WriteFile",
                     "GetSystemDirectoryA", "GetSystemDirectoryW", "GetWindowsDirectoryA",
                     "GetWindowsDirectoryW", "IsDebuggerPresent", "OutputDebugStringA",
                     "OutputDebugStringW", "DebugBreak", "GetThreadContext",
                     "SetThreadContext", "QueueUserAPC", "CreateProcessInternalW",
                     "GetStartupInfoA", "GetStartupInfoW", "GetTimeZoneInformation",
                     "SystemTimeToFileTime", "GetSystemTimeAsFileTime"),
    "ntdll.dll": ("LdrLoadDll", "LdrGetProcedureAddress", "LdrUnloadDll",
                  "NtCreateProcess", "NtCreateProcessEx", "NtCreateThread",
                  "NtCreateThreadEx", "NtOpenProcess", "NtOpenProcessToken",
                  "NtQueryInformationProcess", "NtQuerySystemInformation",
                  "NtQueryVirtualMemory", "NtProtectVirtualMemory",
                  "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
                  "NtReadVirtualMemory", "NtResumeThread", "NtSuspendThread",
                  "NtDelayExecution", "RtlDecompressBuffer", "RtlDecompressFragment",
                  "RtlEqualUnicodeString", "RtlInitUnicodeString",
                  "RtlCreateUserThread", "RtlGetVersion", "RtlUserThreadStart"),
    "user32.dll": ("MessageBoxA", "MessageBoxW", "FindWindowA", "FindWindowW",
                   "GetWindowTextA", "GetWindowTextW", "SetWindowsHookExA",
                   "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
                   "SendInput", "SetCursorPos", "GetCursorPos", "BlockInput",
                   "ShowWindow", "SetWindowPos", "EnumWindows", "GetForegroundWindow",
                   "RegisterHotKey", "GetDC", "ReleaseDC", "LoadCursorA", "LoadCursorW"),
    "advapi32.dll": ("RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA",
                     "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
                     "RegDeleteValueA", "RegDeleteValueW", "RegQueryValueExA",
                     "RegQueryValueExW", "RegDeleteKeyA", "RegDeleteKeyW",
                     "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA",
                     "CreateServiceW", "StartServiceA", "StartServiceW",
                     "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
                     "LookupPrivilegeValueW", "CryptAcquireContextA",
                     "CryptAcquireContextW", "CryptReleaseContext", "RegEnumKeyExA",
                     "RegEnumKeyExW", "OpenProcess", "DuplicateTokenEx",
                     "GetTokenInformation"),
    "ws2_32.dll": ("WSAStartup", "WSACleanup", "socket", "closesocket", "connect",
                   "bind", "listen", "accept", "recv", "send", "recvfrom",
                   "sendto", "gethostbyname", "gethostbyaddr", "inet_addr",
                   "htons", "ntohs", "select", "WSAIoctl", "ioctlsocket",
                   "getaddrinfo", "freeaddrinfo", "setsockopt", "getsockopt",
                   "GetAddrInfoW", "shutdown"),
    "wininet.dll": ("InternetOpenA", "InternetOpenW", "InternetConnectA",
                    "InternetConnectW", "InternetOpenUrlA", "InternetOpenUrlW",
                    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA",
                    "HttpSendRequestW", "InternetReadFile", "InternetWriteFile",
                    "InternetCloseHandle", "InternetSetOptionA", "InternetSetOptionW",
                    "InternetGetConnectedState", "URLDownloadToFileA",
                    "URLDownloadToFileW", "InternetSetStatusCallback"),
    "ole32.dll": ("CoInitialize", "CoInitializeEx", "CoUninitialize", "CoCreateInstance",
                  "CoCreateGuid", "StringFromGUID2", "CLSIDFromString", "OleInitialize",
                  "CoTaskMemAlloc", "CoTaskMemFree", "OleUninitialize"),
    "psapi.dll": ("EnumProcesses", "EnumProcessModules", "GetModuleBaseNameA",
                  "GetModuleBaseNameW", "GetModuleFileNameExA", "GetModuleFileNameExW",
                  "QueryFullProcessImageNameA", "QueryFullProcessImageNameW"),
    "crypt32.dll": ("CryptDecrypt", "CryptEncrypt", "CertOpenStore", "CertOpenSystemStoreA",
                    "CertOpenSystemStoreW", "CryptImportKey", "CryptExportKey",
                    "CryptGenKey", "CryptDeriveKey", "CryptAcquireCertificatePrivateKey"),
    "dnsapi.dll": ("DnsQuery_A", "DnsQuery_W", "DnsRecordListFree", "DnsQueryEx"),
    "mpr.dll": ("WNetAddConnection2A", "WNetAddConnection2W", "WNetOpenEnumA",
                "WNetOpenEnumW", "WNetEnumResourceA", "WNetEnumResourceW"),
}


def _hash_murmur2_32(data: bytes, seed: int = 0) -> int:
    m, r = 0x5BD1E995, 24
    h = (seed ^ len(data)) & 0xFFFFFFFF
    i = 0
    while len(data) - i >= 4:
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * m) & 0xFFFFFFFF
        k ^= k >> r
        k = (k * m) & 0xFFFFFFFF
        h = (h * m) & 0xFFFFFFFF
        h ^= k
        i += 4
    tail = data[i:]
    if tail:
        if len(tail) >= 3:
            h ^= tail[2] << 16
        if len(tail) >= 2:
            h ^= tail[1] << 8
        if tail:
            h ^= tail[0]
            h = (h * m) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * m) & 0xFFFFFFFF
    h ^= h >> 15
    return h & 0xFFFFFFFF


def _hash_murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & 0xFFFFFFFF
    i = 0
    n = len(data)
    while i + 4 <= n:
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
        i += 4
    tail = data[i:]
    if tail:
        k = tail[0] & 0xFF
        if len(tail) >= 2:
            k |= (tail[1] & 0xFF) << 8
        if len(tail) >= 3:
            k |= (tail[2] & 0xFF) << 16
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h & 0xFFFFFFFF


def _hash_djb2(s: str) -> int:
    h = 5381
    for ch in s:
        h = (h * 33 + ord(ch)) & 0xFFFFFFFF
    return h


def _hash_djb2_xor(s: str) -> int:
    h = 5381
    for ch in s:
        h = (((h << 5) + h) ^ ord(ch)) & 0xFFFFFFFF
    return h


def _hash_sdbm(s: str) -> int:
    h = 0
    for ch in s:
        h = (ord(ch) + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def _hash_fnv1a32(s: str) -> int:
    h = 2166136261
    for ch in s:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _hash_fnv1_32(s: str) -> int:
    h = 2166136261
    for ch in s:
        h = (h * 16777619) & 0xFFFFFFFF
        h ^= ord(ch)
    return h


def _api_hash_index() -> dict[int, list[dict]]:
    """hash -> [{dll, func, algo, case}] for every (algo, case-variant)."""
    algos = {
        "murmur2": lambda s: _hash_murmur2_32(s.encode()),
        "murmur2_s97": lambda s: _hash_murmur2_32(s.encode(), 0x9747B28C),
        "murmur3": lambda s: _hash_murmur3_32(s.encode()),
        "djb2": _hash_djb2,
        "djb2_xor": _hash_djb2_xor,
        "sdbm": _hash_sdbm,
        "fnv1a32": _hash_fnv1a32,
        "fnv1_32": _hash_fnv1_32,
    }
    idx: dict[int, list[dict]] = {}
    for dll, fns in _API_HASH_DICT.items():
        for fn in fns:
            for case in ("exact", "lower"):
                s = fn if case == "exact" else fn.lower()
                for algo, fn_hash in algos.items():
                    h = fn_hash(s)
                    idx.setdefault(h, []).append(
                        {"dll": dll, "func": fn, "algo": algo, "case": case})
    return idx


def api_hash_resolver(sample: str, timeout: int = 300) -> dict:
    """Detect runtime API-hash import resolvers (AMAT Track 8 / MalTrak).

    Scans executable sections for 4-byte constants equal to a known-algorithm
    hash of a common Windows API name. High match counts => the binary resolves
    imports at runtime by hash (anti-import-table evasion). Matched names are
    evidence + IOC value (they reveal the resolved API surface).
    """
    t0 = time.time()
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        target = b""
        for s in pe.sections:
            if s.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                raw = (s.get_data() or b"")
                if len(target) < 32 * 1024 * 1024:
                    target += raw
        pe.close()
        if not target:
            return _skipped("api_hash_resolver", "no executable section")
    except Exception as e:
        return {"ok": False, "error": f"api_hash_resolver: {e}",
                "tool": "api_hash_resolver"}

    idx = _api_hash_index()
    matches: list[dict] = []
    seen: set[tuple] = set()
    limit = 96
    for i in range(len(target) - 3):
        v = int.from_bytes(target[i:i + 4], "little")
        for cand in idx.get(v, ()):
            key = (cand["dll"], cand["func"], cand["algo"])
            if key in seen:
                continue
            seen.add(key)
            matches.append({"offset": i, "value": hex(v), **cand})
            if len(matches) >= limit:
                break
        if len(matches) >= limit:
            break

    matches.sort(key=lambda m: (m["dll"], m["func"]))
    by_dll: dict[str, list[str]] = {}
    algos_found: set[str] = set()
    funcs: list[str] = []
    for m in matches:
        by_dll.setdefault(m["dll"], []).append(m["func"])
        algos_found.add(m["algo"])
        if m["func"] not in funcs:
            funcs.append(m["func"])

    signal = len(matches) >= 3
    return {
        "ok": True, "tool": "api_hash_resolver",
        "duration_s": round(time.time() - t0, 2),
        "signal": signal,
        "match_count": len(matches),
        "unique_functions": len(funcs),
        "algorithms": sorted(algos_found),
        "by_dll": by_dll,
        "functions": funcs[:60],
        "hint": ("Runtime API-hash import resolver present: imports resolved "
                 "by hash at runtime (anti-import-table evasion); matched "
                 "names reveal the API surface." if signal else
                 "No known-algorithm API-hash constants found in executable "
                 "sections."),
    }


def signature_match(func_name: str = "", imports: list | None = None,
                    strings: list | None = None, constants: list | None = None,
                    size: int = 0) -> dict:
    """Match a function against signature DBs (crypto/stdlib/winapi).
    Port of RevAI v2_lib.signature_match; DBs from tools/signatures."""
    from pathlib import Path as _P
    sig_dirs = [_P(__file__).resolve().parent / "signatures",
                _P(r"C:\WinRE\internal\signatures")]
    entries = []
    for d in sig_dirs:
        if not d.exists():
            continue
        for path in sorted(d.glob("*.json")):
            try:
                data = json.loads(path.read_text())
                entries.extend(data.get("signatures", []))
            except Exception:
                continue
    if not entries:
        return {"matched": False, "error": "no signature DBs found"}
    imports_set = set(imports or [])
    strings_set = {s.lower() for s in (strings or [])}
    constants_set = set(constants or [])
    threshold = 0.80
    best = None
    best_src = "unknown"
    for entry in entries:
        path = entry.get("_src_db", "")
        ind = entry.get("indicators", {})
        heur = entry.get("heuristics", {})
        score = 0.0
        hits = []
        min_size, max_size = ind.get("min_size"), ind.get("max_size")
        if min_size is not None and size < min_size:
            continue
        if max_size is not None and size > max_size:
            continue
        ext = ind.get("external_symbol_contains", [])
        if ext and any(any(p.lower() in imp.lower() for p in ext)
                       for imp in imports_set):
            score += 0.45
            hits.append("external_symbol")
        want_strings = {s.lower() for s in ind.get("string_refs", [])}
        if want_strings and strings_set & want_strings:
            score += 0.35
            hits.append("string_ref")
        # constants_hex: AES S-box style constants, compared as ints
        want_hex = ind.get("constants_hex", [])
        for h in want_hex:
            try:
                val = int(h, 16)
                if val in constants_set:
                    score += 0.20
                    hits.append(f"constant_{h}")
                    break
            except ValueError:
                continue
        # Heuristic adjustments (RevAI semantics)
        if heur.get("cyclomatic_max") is not None:
            score += 0.10
        if heur.get("call_out_max") is not None:
            score += 0.10
        h_str = {s.lower() for s in heur.get("string_hints", [])}
        if h_str and strings_set & h_str:
            score += 0.10
        score = min(score, entry.get("score", 0.85))
        if score >= threshold and (best is None or score > best["score"]):
            import re as _re
            canonical = _re.sub(r"[^A-Za-z0-9_]", "_", entry["name"])
            best = {"matched": True, "name": canonical,
                    "score": round(score, 3), "matched_rules": hits,
                    "notes": ind.get("notes", ""), "source_db": best_src}
    return best or {"matched": False}


def xor_string_search(sample: str, max_results: int = 30,
                      timeout: int = 120) -> dict:
    """Find XOR/ROL/ADD/SHIFT encoded printable strings — pure-python
    brute force (same candidates contract as RevAI's xorsearch binary)."""
    import math
    try:
        data = Path(sample).read_bytes()
    except OSError as e:
        return {"ok": False, "error": f"file not found: {e}", "candidates": []}
    if len(data) > 8 * 1024 * 1024:
        data = data[:8 * 1024 * 1024]  # cap scan window
    candidates: list[dict] = []
    printable = set(range(0x20, 0x7F))

    def _scan_keyed(key: int, mode: str):
        hits = []
        cur = []
        start = 0
        for i, b in enumerate(data):
            if mode == "xor":
                d = b ^ key
            elif mode == "add":
                d = (b - key) & 0xFF
            elif mode == "sub":
                d = (b + key) & 0xFF
            elif mode == "rol5":
                d = ((b << 5) | (b >> 3)) & 0xFF
            else:
                d = b
            if d in printable:
                if not cur:
                    start = i
                cur.append(d)
            else:
                if len(cur) >= 8:
                    s = bytes(cur).decode("ascii")
                    if sum(c.isalpha() or c.isspace() for c in s) / len(s) >= 0.7:
                        hits.append({"offset": start, "mode": mode,
                                     "key": key, "string": s[:120]})
                        if len(hits) >= max_results:
                            return hits
                cur = []
        return hits

    for mode in ("xor", "add", "sub", "rol5"):
        keys = range(1, 256) if mode == "xor" else range(1, 64)
        for key in keys:
            for h in _scan_keyed(key, mode):
                candidates.append(h)
                if len(candidates) >= max_results:
                    break
            if len(candidates) >= max_results:
                break
        if len(candidates) >= max_results:
            break
    return {"ok": True, "tool": "xor_string_search",
            "candidates": candidates, "total": len(candidates)}


def olevba_analyze(sample: str, timeout: int = 120) -> dict:
    """VBA macro extraction (oletools/olevba)."""
    try:
        magic = Path(sample).read_bytes()[:8]
    except OSError as e:
        return {"ok": False, "error": str(e)[:100]}
    is_ole2 = magic[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    is_zip = magic[:4] == b"PK\x03\x04"
    if not (is_ole2 or is_zip):
        return {"ok": True, "tool": "olevba", "is_office_doc": False, "macros": []}
    import importlib.util
    if importlib.util.find_spec("oletools") is None:
        return _skipped("olevba", "oletools not installed")
    exe = Path(PY).parent / "Scripts" / "olevba.exe"
    cmd = ([str(exe), "--decode", "-c", sample] if exe.is_file()
           else [PY, "-m", "oletools.olevba", "--decode", "-c", sample])
    rc, out, err = _run(cmd, timeout)
    macros = []
    for line in (out or "").splitlines()[:200]:
        low = line.lower()
        if any(k in low for k in ("autoexec", "document_open", "auto_open",
                                  "shell", "createobject", "wscript",
                                  "powershell", "auto_")):
            if line.strip() and not line.startswith("+"):
                macros.append(line.strip()[:200])
    return {"ok": rc == 0, "tool": "olevba", "is_office_doc": True,
            "macros": macros, "returncode": rc}


def peepdf_analyze(sample: str, timeout: int = 120) -> dict:
    """PDF analysis: pdfid element counts/flags + pypdf JS/object extraction.
    (jesparza peepdf.py is Python-2-only; this gives the same evidence —
    JS markers, suspicious objects, embedded files — via maintained tools.)"""
    magic = Path(sample).read_bytes()[:5] if Path(sample).is_file() else b""
    if magic != b"%PDF-":
        return {"ok": True, "tool": "peepdf", "is_pdf": False}
    flags: list[str] = []
    elements: dict = {}
    # 1. pdfid.py (DidierStevens, Py3) — element counts
    pdfid = Path(r"C:\Tools\peepdf\pdfid.py")
    if pdfid.is_file():
        rc, out, err = _run([PY, str(pdfid), sample], timeout)
        # pdfid format: " /Name              <count>" (whitespace, no colon)
        for line in (out or "").splitlines():
            s = line.strip()
            if s.startswith("/") and " " in s:
                parts = s.split()
                if len(parts) >= 2:
                    try:
                        elements[parts[0]] = int(parts[-1])
                    except ValueError:
                        pass
        for name, flag in (("/JS", "JavaScript"), ("/JavaScript", "JavaScript"),
                           ("/OpenAction", "OpenAction"), ("/Launch", "Launch"),
                           ("/EmbeddedFile", "EmbeddedFile"),
                           ("/AcroForm", "AcroForm"), ("/RichMedia", "RichMedia"),
                           ("/ObjStm", "ObjStm"), ("/XFA", "XFA")):
            if elements.get(name, 0) > 0:
                flags.append(flag)
    # 2. pypdf — JS + embedded files (best-effort)
    js_markers: list[str] = []
    embedded: list[str] = []
    try:
        import importlib.util
        if importlib.util.find_spec("pypdf") is not None:
            from pypdf import PdfReader
            reader = PdfReader(sample)
            for i, page in enumerate(reader.pages[:10]):
                try:
                    for annot in (page.get("/Annots") or [])[:10]:
                        o = annot.get_object()
                        js = o.get("/JS")
                        if js:
                            js_markers.append(str(js)[:200])
                except Exception:
                    continue
            try:
                for name in (reader.attachments or {})[:10]:
                    embedded.append(str(name)[:120])
            except Exception:
                pass
    except Exception:
        pass
    return {"ok": True, "tool": "peepdf", "is_pdf": True,
            "elements": elements, "flags": flags,
            "is_suspicious": bool(flags or js_markers),
            "js_markers": js_markers[:10], "embedded": embedded[:10]}


def speakeasy_emulate(sample: str, timeout: int = 900) -> dict:
    """Windows-native PE emulation (Mandiant Speakeasy). Refuses non-PE
    without loading the emulator."""
    import importlib.util
    if importlib.util.find_spec("speakeasy") is None:
        return _skipped("speakeasy", "speakeasy-emulator not installed")
    try:
        head = Path(sample).read_bytes()[:2]
    except OSError as e:
        return {"ok": False, "error": str(e)[:100]}
    if head != b"MZ":
        return {"ok": False, "skipped": True,
                "reason": "not_applicable:only PE emulated"}
    script = (
        "import sys\n"
        "import json\n"
        "from pathlib import Path\n"
        "from speakeasy import Speakeasy\n"
        "p = Path(sys.argv[1])\n"
        "se = Speakeasy()\n"
        "module = se.load_module(str(p))\n"
        "se.run_module(module)\n"
        "report = se.get_json_report()\n"
        "if not isinstance(report, dict):\n"
        "    try:\n"
        "        report = json.loads(str(report))\n"
        "    except Exception:\n"
        "        report = {'raw': str(report)[:4000]}\n"
        "summary = {'speakeasy_ok': True,\n"
        "  'module_base': report.get('module_base'),\n"
        "  'entry_point': report.get('entry_point'),\n"
        "  'key_events': [x for x in (report.get('key_events') or []) if not isinstance(x, dict)][:20] if isinstance(report.get('key_events'), list) else [],\n"
        "  'api_calls': [x for x in (report.get('api_calls') or []) if not isinstance(x, dict)][:20] if isinstance(report.get('api_calls'), list) else [],\n"
        "  'strings': (report.get('strings') if isinstance(report.get('strings'), list) else [])[:20]}\n"
        "print(json.dumps(summary, default=str)[:8000])\n")
    # suppress setuptools pkg_resources DeprecationWarning that pollutes stdout
    _env = os.environ.copy()
    _env["PYTHONWARNINGS"] = _env.get("PYTHONWARNINGS", "ignore::DeprecationWarning")
    rc, out, err = _run([PY, "-c", script, sample], timeout, env=_env)
    if rc != 0:
        return {"ok": False, "error": (err or out)[-400:], "tool": "speakeasy"}
    # parse the LAST JSON object on stdout — setuptools pkg_resources
    # DeprecationWarning can pollute stdout; scanning for the object is robust
    blob = (out or "").strip()
    start = blob.rfind("{")
    end = blob.rfind("}")
    if start >= 0 and end > start:
        try:
            d = json.loads(blob[start:end + 1])
            if isinstance(d, dict):
                return {"ok": True, "tool": "speakeasy", **d}
        except json.JSONDecodeError:
            pass
    try:
        d = json.loads(blob.splitlines()[-1])
        return {"ok": True, "tool": "speakeasy", **d}
    except Exception as e:
        return {"ok": False, "error": f"parse: {e}: {(out or '')[:200]}",
                "tool": "speakeasy"}


def frida_static_probe(sample: str, timeout: int = 120) -> dict:
    """Frida availability + PE hook-candidate probe (no live injection)."""
    out: dict = {"frida_available": False}
    import importlib.util
    if importlib.util.find_spec("frida") is None:
        out["error"] = "frida not installed"
        return out
    out["frida_available"] = True
    try:
        import frida
        out["frida_version"] = frida.__version__
    except Exception:
        pass
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        pe.parse_data_directories()
        hook_candidates = []
        for entry in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or [])[:12]:
            dll = entry.dll.decode(errors="replace")
            for imp in (entry.imports or [])[:5]:
                if imp.name:
                    hook_candidates.append(
                        f"{dll}!{imp.name.decode(errors='replace')}")
        out["hook_candidates"] = hook_candidates[:30]
    except Exception as e:
        out["pe_error"] = str(e)[:200]
    return {"ok": True, "tool": "frida_static_probe", **out}


def r2_decompile(sample: str, function_addrs: list | None = None,
                 timeout: int = 600) -> dict:
    """radare2 disassembly per function (asm — 2nd engine alongside Ghidra).
    Port of RevAI v2_lib.r2_decompile (pdf, not pseudo-C)."""
    exe = Path(r"C:\Tools\radare2\radare2.exe")
    if not exe.is_file():
        return _skipped("r2", "C:\\Tools\\radare2\\radare2.exe missing")
    out: dict = {"r2_ok": False, "disassembly": {}, "engine": "pdf (disasm)"}
    size = Path(sample).stat().st_size if Path(sample).is_file() else 0
    out["size_bytes"] = size
    if size >= 30 * 1024 * 1024:
        return {**out, "skipped": True,
                "reason": "r2 aaa discovery skipped for large sample"}
    if not function_addrs:
        rc, disc, err = _run([str(exe), "-q", "-c", "aa; afl~[0,3]", sample], 120)
        function_addrs = []
        for line in (disc or "").splitlines():
            parts = line.strip().split()
            if parts and parts[0].startswith("0x"):
                function_addrs.append(parts[0])
            if len(function_addrs) >= 5:
                break
        if not function_addrs:
            return {**out, "error": "could not auto-discover function addresses"}
    for addr in function_addrs[:5]:
        rc, pdf_out, err = _run([str(exe), "-q", "-c", f"pdf @ {addr}", sample],
                                timeout)
        if pdf_out:
            out["disassembly"][addr] = pdf_out[:4000]
    out["r2_ok"] = bool(out["disassembly"])
    return {**out, "ok": out["r2_ok"], "tool": "r2_decompile"}


def upx_unpack(sample: str, timeout: int = 120) -> dict:
    """Detect + unpack UPX-packed binaries (writes <sample>.unpacked)."""
    exe = Path(r"C:\Tools\upx\upx.exe")
    if not exe.is_file():
        return _skipped("upx", "C:\\Tools\\upx\\upx.exe missing")
    rc, probe, err = _run([str(exe), "-t", sample], timeout)
    is_packed = rc == 0
    out = {"is_packed": is_packed, "probe": (probe or "")[:200]}
    if not is_packed:
        return {"ok": True, "tool": "upx_unpack", **out}
    unpacked = sample + ".unpacked"
    rc, uout, uerr = _run([str(exe), "-d", sample, "-o", unpacked], timeout)
    out["returncode"] = rc
    if rc == 0 and Path(unpacked).is_file() and Path(unpacked).stat().st_size > 0:
        out["unpacked_path"] = unpacked
        out["upx_ok"] = True
    return {"ok": out.get("upx_ok", False), "tool": "upx_unpack", **out}


def shellcode_extract(sample: str, timeout: int = 300) -> dict:
    """Extract high-entropy executable sections + scdbg emulation.
    Uses pefile (crash-proof) instead of lief."""
    import importlib.util
    import math
    if importlib.util.find_spec("pefile") is None:
        return _skipped("pefile")
    scdbg = Path(r"C:\Tools\scdbg\scdbg.exe")
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        candidates = []
        for s in pe.sections:
            data = s.get_data()
            if len(data) < 16:
                continue
            counts: dict[int, int] = {}
            for b in data:
                counts[b] = counts.get(b, 0) + 1
            total = len(data)
            entropy = -sum((c / total) * math.log2(c / total)
                           for c in counts.values())
            if entropy >= 6.5 and (s.Characteristics & 0x20000000):
                candidates.append((s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                                   entropy, data))
        out_sections = []
        emulated = []
        tmp = Path(sample + ".shellcode.bin")
        for name, ent, data in candidates[:3]:
            out_sections.append({"section": name, "entropy": round(ent, 2),
                                 "size": len(data)})
            if scdbg.is_file() and len(data) <= 512 * 1024:
                tmp.write_bytes(data)
                rc, s_out, s_err = _run([str(scdbg), "-f", str(tmp), "-s", "-120"],
                                        timeout)
                emulated.append({"section": name, "scdbg_head": (s_out or "")[:1500]})
        tmp.unlink(missing_ok=True)
        return {"ok": True, "tool": "shellcode_extract",
                "sections_analyzed": out_sections, "scdbg": emulated,
                "candidates_found": len(candidates)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "tool": "shellcode_extract"}


def dotnet_analyze(sample: str, timeout: int = 600) -> dict:
    """.NET assembly analysis: dnfile metadata + ilspycmd IL/C# decompile.
    Port of RevAI v2_lib.dotnet_analyze (monodis -> ilspycmd on Windows)."""
    import importlib.util
    if importlib.util.find_spec("dnfile") is None:
        return _skipped("dnfile")
    out: dict = {"is_dotnet": False}
    try:
        import dnfile
        pe = dnfile.dnPE(sample)
    except Exception as e:
        return {**out, "error": f"dnfile open failed: {e}", "tool": "dotnet_analyze"}
    out["is_dotnet"] = True
    try:
        out["runtime_version"] = f"v{pe.net.Flags.version}" if pe.net else None
        asm = pe.net.mdtables.Assembly if pe.net and pe.net.mdtables else None
        if asm and asm.rows:
            out["assembly_name"] = asm.rows[0].Name
        mod = pe.net.mdtables.Module if pe.net and pe.net.mdtables else None
        if mod and mod.rows:
            out["module_name"] = mod.rows[0].Name
    except Exception:
        pass
    ilspy = Path.home() / ".dotnet" / "tools" / "ilspycmd.exe"
    if ilspy.is_file():
        # v11 System.CommandLine: bare assembly decompiles to stdout
        rc, il_out, err = _run([str(ilspy), sample], timeout)
        lines = (il_out or "").splitlines()
        out["il_total_lines"] = len(lines)
        out["il_excerpt"] = "\n".join(lines[:120])
        out["csharp_head"] = "\n".join(lines[:80])[:3000]
    return {"ok": True, "tool": "dotnet_analyze", **out}


def z3_solve(sample: str, timeout: int = 120) -> dict:
    """MBA identity solving via the deobfuscation extension (RevAI port)."""
    ext = Path(__file__).resolve().parents[1] / "tools" / "deobfuscation"
    if not (ext / "invoke_z3_or_angr.py").is_file():
        return _skipped("z3_solve", "deobfuscation extension missing")
    sys.path.insert(0, str(ext))
    try:
        import invoke_z3_or_angr as iza  # type: ignore
        iza.ENABLE_DEOBFUSCATION_PASS_DEFAULT = True
        r = iza.invoke_z3_or_angr("mba_identity", sample, timeout=timeout)
        return {"ok": True, "tool": "z3_solve", "result": r}
    except Exception as e:
        return {"ok": False, "error": str(e)[:250], "tool": "z3_solve"}


def angr_analyze(sample: str, timeout: int = 300) -> dict:
    """CFF dispatcher analysis (angr via deobfuscation extension, RevAI port).
    Windows angr is functional but heavier — honest degradation applies.
    Env-overrides point the vendored extension at Windows paths (the
    extension itself is untouched platform code)."""
    import os as _os
    ext = Path(__file__).resolve().parents[1] / "tools" / "deobfuscation"
    if not (ext / "invoke_z3_or_angr.py").is_file():
        return _skipped("angr_analyze", "deobfuscation extension missing")
    _os.environ["CFF_DEFLATTEN_PY"] = str(
        Path(__file__).resolve().parent / "deobfuscation" / "cff_deflatten.py")
    _os.environ["ANGR_PYTHON"] = sys.executable
    gh = None
    for g in Path(r"C:\Tools").glob("ghidra_*_PUBLIC"):
        if (g / "support" / "analyzeHeadless.bat").is_file():
            gh = g
            break
    if gh:
        _os.environ["GHIDRA_ANALYZE_HEADLESS"] = str(gh / "support" / "analyzeHeadless.bat")
    sys.path.insert(0, str(ext))
    try:
        import invoke_z3_or_angr as iza  # type: ignore
        iza.ENABLE_DEOBFUSCATION_PASS_DEFAULT = True
        r = iza.invoke_z3_or_angr("cff_dispatcher", sample, timeout=timeout)
        return {"ok": True, "tool": "angr_analyze", "result": r}
    except Exception as e:
        return {"ok": False, "error": str(e)[:250], "tool": "angr_analyze"}


def ghidra_decompile(sample: str, function_addr: str = "",
                     timeout: int = 1800) -> dict:
    """Ghidra decompile — pyghidra fast-path when configured (needs
    GHIDRA_INSTALL_DIR), headless + post-script fallback otherwise.
    Same method as RevAI's RPC; pyghidra removes the headless cold-start."""
    # fast-path: pyghidra flat API (much faster than headless per-call)
    try:
        gid = os.environ.get("GHIDRA_INSTALL_DIR", "")
        if gid:
            import pyghidra
            pyghidra.start()
            with pyghidra.open_program(sample) as flat:
                func = (flat.get_function_at(flat.to_addr(function_addr))
                        if function_addr else None)
                if func is None:
                    func = flat.get_function_containing(
                        flat.get_symbol("entry").get_address())
                if func is not None:
                    from ghidra.app.decompiler import DecompInterface
                    di = DecompInterface()
                    di.openProgram(flat.get_program())
                    res = di.decompileFunction(func, 60, None)
                    if res and res.getDecompiledFunction():
                        code = res.getDecompiledFunction().getC()
                        return {"ok": True, "tool": "ghidra_decompile",
                                "engine": "pyghidra",
                                "function": str(func),
                                "code": code[:12000]}
    except Exception as e:
        # graceful fall-through to headless on any pyghidra failure
        pass
    import tempfile
    ghidra = None
    for g in Path(r"C:\Tools").glob("ghidra_*_PUBLIC"):
        if (g / "support" / "analyzeHeadless.bat").is_file():
            ghidra = g
            break
    java = Path(__file__).resolve().parent / "ghidra_scripts" / "DecompileFunc.java"
    if not ghidra or not java.is_file():
        return _skipped("ghidra_decompile", "ghidra or DecompileFunc.java missing")
    proj = tempfile.mkdtemp(prefix="winre-gh-dec-")
    cmd = [str(ghidra / "support" / "analyzeHeadless.bat"), proj, "dec",
           "-import", sample,
           "-scriptPath", str(java.parent),
           "-postScript", "DecompileFunc.java", "GHIDRA_DECOMP_FUNC",
           "-deleteProject"]
    env = os.environ.copy()
    env["GHIDRA_DECOMP_FUNC"] = function_addr or "entry"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env,
                           timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"headless decompile timeout {timeout}s",
                "tool": "ghidra_decompile"}
    blob = (p.stdout or "")
    # DecompileFunc.java emits {"function": ...} — Ghidra INFO lines may
    # appear before AND after it. raw_decode parses the first complete
    # object and ignores trailing noise (json.loads would choke on it).
    start = blob.find('{"function"')
    if start < 0:
        start = blob.rfind("{")
    if start < 0:
        return {"ok": False, "error": "no JSON from post-script",
                "tail": blob[-300:], "tool": "ghidra_decompile"}
    try:
        d, _ = json.JSONDecoder().raw_decode(blob[start:])
        return {"ok": True, "tool": "ghidra_decompile", "engine": "headless",
                **d}
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"parse: {e}", "tail": blob[start:start + 300],
                "tool": "ghidra_decompile"}


def main() -> int:
    import argparse
    # KB-derived gap tools (pure-python / r2) live in kb_gap_tools.py
    try:
        from kb_gap_tools import TOOL_FUNCS as KB_TOOL_FUNCS
    except Exception:
        KB_TOOL_FUNCS = {}
    TOOL_FUNCS = {"capa": capa, "floss": floss, "lief": lief_parse,
                  "diec": diec, "ilspy": ilspy, "yarascan": yarascan,
                  "strings": strings,
                  "pe_import_signals": pe_import_signals,
                  "api_hash_resolver": api_hash_resolver,
                  "signature_match": signature_match,
                  "xor_string_search": xor_string_search,
                  "olevba": olevba_analyze, "peepdf": peepdf_analyze,
                  "speakeasy": speakeasy_emulate,
                  "frida_static_probe": frida_static_probe,
                  "r2_decompile": r2_decompile, "upx": upx_unpack,
                  "shellcode_extract": shellcode_extract,
                  "dotnet_analyze": dotnet_analyze,
                  "z3_solve": z3_solve, "angr_analyze": angr_analyze,
                  "ghidra_decompile": ghidra_decompile,
                  **KB_TOOL_FUNCS}
    ap = argparse.ArgumentParser(description="RevAI-parity static evidence wrappers")
    ap.add_argument("tool", choices=list(TOOL_FUNCS.keys()) + ["all"])
    ap.add_argument("sample")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--json-args", default=None,
                    help="base64-encoded JSON kwargs for the tool call")
    a = ap.parse_args()
    kwargs = {}
    if a.json_args:
        import base64 as _b64
        try:
            kwargs = json.loads(_b64.b64decode(a.json_args).decode("utf-8"))
            if not isinstance(kwargs, dict):
                kwargs = {}
        except Exception:
            kwargs = {}
    if a.tool == "all":
        core = ("capa", "floss", "lief", "diec", "yarascan", "strings",
                "pe_import_signals", "api_hash_resolver", "xor_string_search",
                "crypto_constants", "mitigations", "ioc_extract")
        out = {t: TOOL_FUNCS[t](a.sample) for t in core}
    elif a.tool == "signature_match":
        # signature_match is the odd tool: first param is func_name, no sample
        out = {a.tool: TOOL_FUNCS[a.tool](**kwargs)}
    else:
        out = {a.tool: TOOL_FUNCS[a.tool](a.sample, **kwargs)}
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
