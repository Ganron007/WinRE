#!/usr/bin/env python3
"""procmon_approvelists.py — Noriben-grade Procmon noise filtering & path generalization.

Selective port of the curated approvelists from Noriben (v2.1.0, Brian Baskin)
into compiled, high-performance regex sets. Filters out 14+ years of cataloged
Windows OS background noise (search indexer, font caches, thumbcaches, BAM,
NetworkService temp, telemetry, CryptnetUrlCache, etc.) while preserving genuine
malware behaviors (persistence keys, process trees, dropped binaries).
"""
from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Path Generalization
# ---------------------------------------------------------------------------
_ENV_REPLACEMENTS = [
    (r"%SystemRoot%", r"(?:[A-Za-z]:\\Windows|\\Windows)"),
    (r"%WinDir%", r"(?:[A-Za-z]:\\Windows|\\Windows)"),
    (r"%SystemDrive%", r"[A-Za-z]:"),
    (r"%ProgramFiles%", r"[A-Za-z]:\\Program Files"),
    (r"%ProgramFiles(x86)%", r"[A-Za-z]:\\Program Files \(x86\)"),
    (r"%AllUsersProfile%", r"(?:[A-Za-z]:\\ProgramData|[A-Za-z]:\\Users\\All Users)"),
    (r"%ProgramData%", r"[A-Za-z]:\\ProgramData"),
    (r"%UserProfile%", r"[A-Za-z]:\\Users\\[^\\]+"),
    (r"%AppData%", r"[A-Za-z]:\\Users\\[^\\]+\\AppData\\Roaming"),
    (r"%LocalAppData%", r"[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local"),
    (r"%Temp%", r"[A-Za-z]:\\(?:Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\Temp)"),
]


def _init_generalize_patterns() -> list[tuple[re.Pattern, str]]:
    """Build pattern list for path generalization."""
    pats = []
    # Dynamic runtime environment variables
    env_vars = [
        ("Temp", r"%TEMP%"),
        ("LocalAppData", r"%LOCALAPPDATA%"),
        ("AppData", r"%APPDATA%"),
        ("UserProfile", r"%USERPROFILE%"),
        ("ProgramData", r"%PROGRAMDATA%"),
        ("ProgramFiles(x86)", r"%PROGRAMFILES(X86)%"),
        ("ProgramFiles", r"%PROGRAMFILES%"),
        ("SystemRoot", r"%SYSTEMROOT%"),
        ("WinDir", r"%WINDIR%"),
        ("SystemDrive", r"%SYSTEMDRIVE%"),
    ]
    # 1. High-priority specific folders (Temp in Windows or Users)
    pats.append((re.compile(r"^[A-Za-z]:\\Windows\\Temp", re.I), r"%TEMP%"))
    pats.append((re.compile(r"^[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local\\Temp", re.I), r"%TEMP%"))

    # 2. Dynamic runtime environment variables
    for var_name, placeholder in env_vars:
        val = os.environ.get(var_name)
        if val and len(val) > 2:
            try:
                escaped = re.escape(val)
                pats.append((re.compile(escaped, re.I), placeholder))
            except Exception:
                pass

    # Generic Windows fallbacks (for Linux control plane or non-expanded envs)
    fallbacks = [
        (re.compile(r"^[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local\\Temp", re.I), r"%TEMP%"),
        (re.compile(r"^[A-Za-z]:\\Windows\\Temp", re.I), r"%TEMP%"),
        (re.compile(r"^[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local", re.I), r"%LOCALAPPDATA%"),
        (re.compile(r"^[A-Za-z]:\\Users\\[^\\]+\\AppData\\Roaming", re.I), r"%APPDATA%"),
        (re.compile(r"^[A-Za-z]:\\Users\\[^\\]+", re.I), r"%USERPROFILE%"),
        (re.compile(r"^[A-Za-z]:\\ProgramData", re.I), r"%PROGRAMDATA%"),
        (re.compile(r"^[A-Za-z]:\\Program Files \(x86\)", re.I), r"%PROGRAMFILES(X86)%"),
        (re.compile(r"^[A-Za-z]:\\Program Files", re.I), r"%PROGRAMFILES%"),
        (re.compile(r"^[A-Za-z]:\\Windows", re.I), r"%WINDIR%"),
    ]
    pats.extend(fallbacks)
    return pats


_GENERALIZE_PATTERNS = _init_generalize_patterns()


def generalize_path(path: str) -> str:
    """Replace user/system specific path prefixes with generic %ENV% variables."""
    if not path or not isinstance(path, str):
        return ""
    result = path
    for pat, repl in _GENERALIZE_PATTERNS:
        if pat.search(result):
            result = pat.sub(repl, result)
            break
    return result


# ---------------------------------------------------------------------------
# Curated Approvelists (Noriben v2.1.0 Curated Filters)
# ---------------------------------------------------------------------------

# 1. Global Process Approvelist (processes ignored across all event types)
_RAW_GLOBAL_PATTERNS = [
    r"VMwareUser\.exe",
    r"CaptureBAT\.exe",
    r"SearchIndexer\.exe",
    r"Fakenet.*\.exe",
    r"idaq.*\.exe",
    r"ngen\.exe",
    r"ngentask\.exe",
    r"consent\.exe",
    r"taskhost(?:w)?\.exe",
    r"RepUx\.exe",
    r"RepMgr64\.exe",
    r"Ecat\.exe",
    r"OneDriveStandaloneUpdater\.exe",
    r"WindowsApps\\Microsoft\.Windows\.Photos.*\\Microsoft\.Photos\.exe",
    r"GoogleUpdate\.exe",
    r"MicrosoftEdgeUpdate\.exe",
    r"EDGEMITMP_.*\.tmp\\setup\.exe",
    r"Packages\\Microsoft\.Windows\.Cortana",
    r"Procmon(?:64)?\.exe",
    r"pe-sieve.*\.exe",
    r"hollows_hunter.*\.exe",
]

# 2. Command Line Approvelist (benign system process invocations)
_RAW_CMD_PATTERNS = [
    r"AppData\\Local\\Microsoft\\OneDrive\\StandaloneUpdater\\OneDriveSetup\.exe",
    r"%SystemRoot%\\system32\\wbem\\wmiprvse\.exe",
    r"%SystemRoot%\\system32\\wscntfy\.exe",
    r"wuauclt\.exe",
    r"jqs\.exe",
    r"avgrsa\.exe",
    r"avgcsrva\.exe",
    r"avgidsagenta\.exe",
    r"TCPView\.exe",
    r"%WinDir%\\System32\\mobsync\.exe",
    r"XblGameSaveTask\.exe",
    r"xtac\.exe",
    r"XtaCache\.exe",
    r"%WinDir%\\system32\\conhost\.exe",
    r"%WinDir%\\System32\\RuntimeBroker\.exe -Embedding",
    r"%WinDir%\\uus\\packages\\preview\\ARM64\\MoUsoCoreWorker\.exe",
]

# 3. File Approvelist (benign file operations, temp files, read-only churn)
_RAW_FILE_PATTERNS = [
    r"%AllUsersProfile%\\Application Data\\Microsoft\\OFFICE\\DATA",
    r"%AllUsersProfile%\\Microsoft\\Windows\\AppRepository\\Packages\\Microsoft.*\\ActivationStore",
    r"%AllUsersProfile%\\Microsoft\\MapData",
    r"%AllUsersProfile%\\Microsoft\\Network\\Downloader\\edb\.chk",
    r"%AllUsersProfile%\\Microsoft\\RAC",
    r"%AllUsersProfile%\\Microsoft\\Windows\\AppRepository\\StateRepository",
    r"%AppData%\\Microsoft\\Proof",
    r"%AppData%\\Microsoft\\Templates",
    r"%AppData%\\Microsoft\\Windows\\Recent\\AutomaticDestinations",
    r"%LocalAppData%\\Google\\Drive\\sync_config\.db",
    r"%LocalAppData%\\GDIPFONTCACHEV1\.DAT",
    r"%LocalAppData%\\Microsoft\\OneDrive\\StandaloneUpdater",
    r"%LocalAppData%\\Microsoft\\TokenBroker\\Cache",
    r"%LocalAppData%\\Microsoft\\VSApplicationInsights\\vstelAIF",
    r"%LocalAppData%\\Packages\\Microsoft\.Windows\.Photos_",
    r"%SystemRoot%\\assembly",
    r"%SystemRoot%\\Microsoft\.NET\\Framework64",
    r"%SystemRoot%\\Prefetch",
    r"%SystemRoot%\\system32\\wbem\\Logs",
    r"%SystemRoot%\\System32\\LogFiles\\Scm",
    r"%SystemRoot%\\System32\\Tasks\\Microsoft\\Windows",
    r"%UserProfile%\\Recent",
    r"%UserProfile%\\Local Settings\\History\\History\.IE5",
    r"%WinDir%\\AppCompat\\Programs\\RecentFileCache\.bcf",
    r"%WinDir%\\AppCompat\\pca\\PcaAppLaunchDic\.txt",
    r"%WinDir%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\Fonts",
    r"%WinDir%\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Dlna",
    r"%WinDir%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp",
    r"%WinDir%\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp",
    r"%WinDir%\\SoftwareDistribution\\DataStore",
    r"%WinDir%\\SoftwareDistribution\\ReportingEvents\.log",
    r"%WinDir%\\System32\\catroot2",
    r"%WinDir%\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData",
    r"%WinDir%\\System32\\spool\\drivers",
    r"%WinDir%\\System32\\spp\\store",
    r"%WinDir%\\System32\\sru\\SRU",
    r"%WinDir%\\Temp\\fwtsqmfile.*\.sqm",
    r"%WinDir%\\XtaCache",
    # Specific file names
    r"desktop\.ini$",
    r"Thumbs\.db$",
    r"Google\\Chrome\\User Data\\.*\.tmp",
    r"MAILSLOT\\NET\\NETLOGON",
    r"Microsoft\\Windows\\Explorer\\iconcache_.*",
    r"Microsoft\\Windows\\Explorer\\thumbcache_.*\.db",
    r"ProgramData\\USOPrivate\\UpdateStore\\store.*",
    r"Windows\\Temporary Internet Files\\counters\.dat",
    # Read-only access masks that indicate queries rather than plant/write intent
    r"Desired Access: (?:Execute/Traverse|Synchronize|Generic Read/Execute|Read EA|Read Data/List Directory|Read Attributes)",
]

# 4. Registry Approvelist (benign OS configuration, explorer MRUs, diagnostics)
_RAW_REG_PATTERNS = [
    r"}\\DefaultObjectStore",
    r"}\\DeliveryOptimization\\Swarms",
    r"}\\LocalState\\SessionSummaryData",
    r"HKCR$",
    r"HKCR\\AllFilesystemObjects\\shell",
    r"HKCU$",
    r"HKCU\\Printers\\DevModePerUse",
    r"HKCU\\SessionInformation\\ProgramCount",
    r"HKCU\\Software$",
    r"HKCU\\Software\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment\\SideBySide",
    r"HKCU\\Software\\Classes\\Local Settings\\MuiCache",
    r"HKCU\\Software\\Classes\\Local Settings\\MrtCache",
    r"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\SyncMgr",
    r"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\Microsoft.*\\PersistedTitleBarData",
    r"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell",
    r"HKCU\\Software\\Microsoft\\Calc$",
    r"HKCU\\Software\\Microsoft\\.*\\Window_Placement",
    r"HKCU\\Software\\Microsoft\\input\\TypingInsights\\Insights",
    r"HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs",
    r"HKCU\\Software\\Microsoft\\Notepad",
    r"HKCU\\Software\\Microsoft\\Office",
    r"HKCU\\Software\\Microsoft\\Shared Tools",
    r"HKCU\\Software\\Microsoft\\SystemCertificates\\Root$",
    r"HKCU\\Software\\Microsoft\\VisualStudio",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CIDOpen",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CIDSave\\Modules\\GlobalSettings",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\.*MRU.*",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Modules",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage2",
    r"HKCU\\Software\\Microsoft\\Windows\\Currentversion\\Explorer\\StreamMRU",
    r"HKCU\\Software\\Microsoft\\Windows\\Currentversion\\Explorer\\Streams",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\HomeGroup",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad",
    r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Telephony",
    r"HKCU\\Software\\Microsoft\\Windows\\Shell",
    r"HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    r"HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags",
    r"HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
    r"HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    r"HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\Bags",
    r"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Devices",
    r"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\PrinterPorts",
    r"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\UserSelectedDefault",
    r"HKCU\\Software\\Policies",
    r"HKLM\\.*\\Enum$",
    r"HKLM\\Software$",
    r"HKLM\\Software\\Microsoft\\Cryptography\\RNG\\Seed",
    r"HKLM\\Software\\Microsoft$",
    r"HKLM\\SOFTWARE\\Microsoft\\Device Association Framework\\Store",
    r"HKLM\\Software\\MICROSOFT\\Dfrg\\Statistics",
    r"HKLM\\Software\\Microsoft\\Reliability Analysis\\RAC",
    r"HKLM\\Software\\MICROSOFT\\SystemCertificates",
    r"HKLM\\SOFTWARE\\Microsoft\\Tracing",
    r"HKLM\\Software\\Microsoft\\WBEM",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\PackageRepair",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\PolicyOverdue",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State\\Machine\\Extension-List",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache\\Paths",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Rende",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Telephony",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WaaSAssessment",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Orchestrator",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Wosc\\Client\\Persistent\\ClientState",
    r"HKLM\\Software\\Microsoft\\Windows Media Player NSS",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Appraiser",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Inventory",
    r"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications",
    r"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Prefetcher",
    r"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Print",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\.*\\RefCount$",
    r"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Tracing",
    r"HKLM\\Software\\Policies",
    r"HKLM\\System\\CurrentControlSet\\Control\\Class\\{.*-E325-11CE-BFC1-08002BE10318}",
    r"HKLM\\System\\CurrentControlSet\\Control\\DeviceClasses",
    r"HKLM\\System\\CurrentControlSet\\Control\\DeviceContainers",
    r"HKLM\\System\\CurrentControlSet\\Control\\hivelist\\REGISTRY\\A",
    r"HKLM\\System\\CurrentControlSet\\Control\\MediaProperties",
    r"HKLM\\System\\CurrentControlSet\\Control\\Network",
    r"HKLM\\System\\CurrentControlSet\\Control\\NetworkSetup2",
    r"HKLM\\System\\CurrentControlSet\\Control\\Nsi",
    r"HKLM\\System\\CurrentControlSet\\Control\\Print\\Environments",
    r"HKLM\\System\\CurrentControlSet\\Enum",
    r"HKLM\\System\\CurrentControlSet\\Services\\bam\\State\\UserSettings",  # Windows Background Activity Moderator
    r"HKLM\\System\\CurrentControlSet\\Services\\Eventlog",
    r"HKLM\\System\\CurrentControlSet\\Services\\iphlpsvc",
    r"HKLM\\System\\CurrentControlSet\\Services\\ksthunk",
    r"HKLM\\System\\CurrentControlSet\\Services\\NetBT",
    r"HKLM\\System\\CurrentControlSet\\Services\\RasMan",
    r"HKLM\\System\\CurrentControlSet\\Services\\SharedAccess\\Epoch2",
    r"HKLM\\System\\CurrentControlSet\\Services\\Tcpip",
    r"HKLM\\System\\CurrentControlSet\\Services\\tunnel",
    r"HKLM\\System\\CurrentControlSet\\Services\\W32Time",
    r"HKLM\\System\\CurrentControlSet\\Services\\WinSock2",
    r"HKLM\\System\\CurrentControlSet\\Services\\WSD",
    r"HKLM\\System\\CurrentControlSet\\Services\\VSS\\Diag",
    r"HKLM\\SYSTEM\\Maps",
    r"HKLM\\SYSTEM\\Software\\Microsoft\\TIP\\AggregateResults\\data$",
    r"HKLM\\SYSTEM\\WaaS\\WaaSMedic\\State",
    r"HKU\\\.DEFAULT\\Printers",
    r"HKU\\\.DEFAULT\\SOFTWARE\\Classes\\Local Settings\\MuiCache",
    r"Microsoft\\Device Association Framework\\Store\\DAFUPnPProvide",
    r"Microsoft\\EdgeUpdate",
    r"Software\\Microsoft\\Multimedia\\Audio",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MenuOrde",
    r"Software\\Microsoft\\Windows\\ShellNoRoam\\Bags",
    r"Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Usage",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\\.doc",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    r"UserAssist\\{.*}",
]

# 5. DLL Load Approvelist (standard system directories & Python harness)
_RAW_DLL_PATTERNS = [
    r"%WinDir%\\System32\\",
    r"%WinDir%\\SysWOW64\\",
    r"%WinDir%\\WinSxS\\",
    r"%WinDir%\\Microsoft\.NET\\",
    r"%ProgramFiles%\\",
    r"%ProgramFiles\(x86\)%\\",
    r"%WinDir%\\assembly\\NativeImages_v4\.0",
    r"Python3\d*\\",  # Lab harness interpreter
]


def _compile_patterns(raw_list: list[str]) -> re.Pattern:
    """Expand environment variables and compile a list of patterns into a single regex."""
    expanded = []
    for item in raw_list:
        p = item.strip()
        for env, repl in _ENV_REPLACEMENTS:
            p = re.sub(re.escape(env), lambda m, r=repl: r, p, flags=re.I)
        p = p.replace(r"\*", r".*")
        expanded.append(p)
    pattern_str = "(?:" + "|".join(expanded) + ")"
    return re.compile(pattern_str, re.I)


GLOBAL_NOISE_RE = _compile_patterns(_RAW_GLOBAL_PATTERNS)
CMD_NOISE_RE = _compile_patterns(_RAW_CMD_PATTERNS)
FILE_NOISE_RE = _compile_patterns(_RAW_FILE_PATTERNS)
REG_NOISE_RE = _compile_patterns(_RAW_REG_PATTERNS)
DLL_NOISE_RE = _compile_patterns(_RAW_DLL_PATTERNS)


# ---------------------------------------------------------------------------
# Filter Predicates
# ---------------------------------------------------------------------------

def is_global_noise(process_name: str) -> bool:
    """Check if process is in the global approvelist (known background noise)."""
    if not process_name:
        return False
    return bool(GLOBAL_NOISE_RE.search(process_name))


def is_cmd_noise(cmdline: str, process_name: str = "") -> bool:
    """Check if command line is benign OS/service execution."""
    if is_global_noise(process_name):
        return True
    if not cmdline:
        return False
    return bool(CMD_NOISE_RE.search(cmdline))


def is_file_noise(path: str, operation: str = "", detail: str = "", process_name: str = "") -> bool:
    """Check if file operation is benign Windows background activity."""
    if is_global_noise(process_name):
        return True
    if not path:
        return True
    if FILE_NOISE_RE.search(path):
        return True
    if detail and FILE_NOISE_RE.search(detail):
        return True
    return False


def is_reg_noise(path: str, operation: str = "", process_name: str = "") -> bool:
    """Check if registry operation is benign OS churn."""
    if is_global_noise(process_name):
        return True
    if not path:
        return True
    return bool(REG_NOISE_RE.search(path))


def is_dll_noise(path: str, process_name: str = "") -> bool:
    """Check if loaded image is from a standard system library path or harness."""
    if is_global_noise(process_name):
        return True
    if not path:
        return False
    return bool(DLL_NOISE_RE.search(path))


# ---------------------------------------------------------------------------
# Resilient CSV Reader
# ---------------------------------------------------------------------------

def iter_procmon_csv(csv_path: Path, max_rows: int = 3_000_000) -> Iterator[dict[str, str]]:
    """Yield cleaned rows from a Procmon CSV with encoding recovery and field normalization."""
    if not csv_path.is_file() or csv_path.stat().st_size == 0:
        return

    # Try utf-8-sig first, fall back to latin-1 on encoding error
    encoding = "utf-8-sig"
    try:
        with csv_path.open("r", encoding=encoding, errors="strict", newline="") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                yield {k.strip(): (v or "").strip() for k, v in row.items() if k}
        return
    except UnicodeDecodeError:
        encoding = "latin-1"

    with csv_path.open("r", encoding=encoding, errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            yield {k.strip(): (v or "").strip() for k, v in row.items() if k}
