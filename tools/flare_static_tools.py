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
import subprocess
import sys
from pathlib import Path

PY = sys.executable or r"C:\Python313\python.exe"
CAPA_RULES = r"C:\Tools\capa-rules"
DIE_DIR = r"C:\Tools\die"
ILSPY = str(Path.home() / ".dotnet" / "tools" / "ilspycmd.exe")
YARA_RULES_DIR = r"C:\Tools\yara-rules"
STRINGS64 = r"C:\Tools\sysinternals\strings64.exe"


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
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
    if not rules_dir.is_dir() or not any(rules_dir.rglob("*.yar")):
        return {"ok": True, "tool": "yarascan", "hits": [],
                "skipped": "no rules staged in C:\\Tools\\yara-rules (operator adds curated sets)"}
    rc, out, err = _run([yr, "scan", "-f", "text-only", str(rules_dir), sample], timeout)
    hits = [l for l in (out or "").splitlines() if l.strip()]
    return {"ok": True, "tool": "yarascan", "hits": hits[:40],
            "total": len(hits)}


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


def main() -> int:
    import argparse
    TOOL_FUNCS = {"capa": capa, "floss": floss, "lief": lief_parse,
                  "diec": diec, "ilspy": ilspy, "yarascan": yarascan,
                  "strings": strings}
    ap = argparse.ArgumentParser(description="RevAI-parity static evidence wrappers")
    ap.add_argument("tool", choices=["capa", "floss", "lief", "diec", "ilspy",
                                     "yarascan", "strings", "all"])
    ap.add_argument("sample")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.tool == "all":
        out = {t: fn(a.sample) for t, fn in TOOL_FUNCS.items()}
    else:
        out = {a.tool: TOOL_FUNCS[a.tool](a.sample)}
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
