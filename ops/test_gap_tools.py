#!/usr/bin/env python3
"""test_gap_tools.py — host-runnable unit tests for the KB-derived gap tools
(2026-09-07). VM-only tools (pefile/r2/goresym-dependent) are exercised via
the VM smoke script; anything pure-python is asserted here.

Run: python ops/test_gap_tools.py
"""
import base64
import json
import shutil
import struct
import sys
import tempfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

FAILS = []


def check(name, cond, detail=""):
    print(f"  [{'OK' if cond else 'FAIL'}] {name} {detail}")
    if not cond:
        FAILS.append(name)


# ── kb_gap_tools (pure-python pieces) ───────────────────────────────────────
import kb_gap_tools as kb

td = Path(tempfile.mkdtemp(prefix="winre-test-"))

print("[1] rtf_predecode")
rtf = td / "evil.rtf"
ole2 = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 128
rtf.write_bytes(b"{\\rtf1\\ansi evil \\'68\\'74\\'74\\'70:\\'2f\\'2f x "
                + b"{\\object\\objdata\\bin" + str(len(ole2)).encode()
                + b" " + ole2 + b"}}")
r = kb.rtf_predecode(str(rtf))
check("is_rtf", r.get("is_rtf") is True)
check("embedded_ole2", r.get("embedded_ole2") is True, str(r.get("ole2_blob_count")))
check("hex_escapes", r.get("hex_escape_count") >= 5, str(r.get("hex_escape_count")))

print("[2] script_decode")
payload = b"powershell -enc " + base64.b64encode(
    zlib.compress(b"function Evil { $x = 'http://evil.example/c2'; iex $x }"))
s = kb.script_decode(str(td / "sc.ps1"))
(td / "sc.ps1").write_bytes(payload)
s = kb.script_decode(str(td / "sc.ps1"))
check("script_layers", s.get("layers"), str(s.get("layers")))
check("embedded_url", any("evil.example" in u for u in s.get("embedded", {}).get("urls", [])))

print("[3] ioc_extract")
blob = (b"payment 1BoatSLRHtKNngkdXEeobR76b53LETtpyT btc | "
        b"hxxp://evil[.]example/load.exe | 45.32.1.9 | evil.net")
r = kb.ioc_extract(str(td / "ioc.bin"))
(td / "ioc.bin").write_bytes(blob)
r = kb.ioc_extract(str(td / "ioc.bin"))
check("wallet_btc", bool(r.get("wallets", {}).get("btc")), str(r.get("wallets")))
check("url_defanged", any("evil" in u for u in r.get("urls", [])), str(r.get("urls")))
check("domain", bool(r.get("domains")), str(r.get("domains")))
check("ip", bool(r.get("ips")), str(r.get("ips")))

print("[4] rolling_xor (pe-in-pe known-plaintext)")
# alternating 2-byte key: k1 on even bytes (M, 0x90, 0x03...), k2 on odd (Z, 0x00, 0x00...)
k1, k2 = 0x5A, 0x3C
pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
enc = bytes(pe[i] ^ (k1 if i % 2 == 0 else k2) for i in range(len(pe)))
(td / "nested.bin").write_bytes(b"\x00" * 64 + enc)
r = kb.rolling_xor(str(td / "nested.bin"))
check("pe_in_pe_key", any(x.get("kind") == "pe-in-pe" for x in r.get("results", [])),
      str(r.get("results")))

print("[5] string_decode_emulate decode helpers")
dec = kb._decode_with(bytes([0x68, 0x65, 0x6C, 0x6C, 0x6F]), b"\x01", "xor")
check("xor_decode", dec == bytes(b ^ 1 for b in b"hello"), dec.hex())
enc = bytes((b - 2) & 0xFF for b in b"hello")
dec = kb._decode_with(enc, b"\x02", "add")
check("add_decode", dec == b"hello", f"{enc.hex()} -> {dec.hex()}")
check("printable_ratio", kb._printable_ratio(b"hello world!!") == 1.0)

print("[6] yara curation")
from winre import yara_gen
c = yara_gen._curate(["the", "and", "VirtualAlloc", "http://evil.example/path"], [])
check("curation_warns", bool(c["warnings"]), str(c["warnings"]))
c2 = yara_gen._curate(["http://evil.example/a-very-long-path/load"], [])
check("curation_clean", c2["sound"] is True, str(c2))

print("[7] reporting._behavior_context")
from winre import reporting
ev = {"strings_tool": {"strings": ["C:\\Users\\x\\AppData\\Roaming\\a.exe",
                                   "Global\\EvilMutex", "HKLM\\SOFTWARE\\X",
                                   "/silent", "-install", "--config"]},
      "capa": {"capabilities": [{"name": "check for virtual environment"},
                                {"name": "sleep a long time"}]}}
bc = reporting._behavior_context(ev)
check("kill_switch", bool(bc["kill_switch"]), str(bc["kill_switch"]))
check("cli", any("--config" in c for c in bc["cli"]), str(bc["cli"]))
check("artifacts", bool(bc["artifacts"]["mutexes"]), str(bc["artifacts"]))

print("[8] procmon_post on synthetic CSV")
from winre import procmon_post
dyn = td / "dyn"
dyn.mkdir(exist_ok=True)
(dyn / "procmon.csv").write_text(
    "Time of Day,Process Name,PID,Operation,Path,Detail,Result\n"
    "12:00:01.1,evil.exe,100,RegSetValue,"
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,val,SUCCESS\n"
    "12:00:02.2,evil.exe,100,Process Create,parent.exe,"
    "powershell -enc ABCDEF==,SUCCESS\n"
    "12:00:03.3,evil.exe,100,WriteFile,C:\\Users\\x\\AppData\\Roaming\\b.exe,,SUCCESS\n",
    encoding="utf-8")
r = procmon_post.build_procmon_report(dyn)
check("run_key", bool(r.get("persistence", {}).get("run_key")), str(r.get("persistence")))
check("drop_file", bool(r.get("persistence", {}).get("drop_file")))
check("spoof_suspect", bool(r.get("spoofing_suspects")), str(r.get("spoofing_suspects")))
check("timeline_csv", (dyn / "behavior_timeline.csv").is_file())

print("[9] casepack (7z) — synthetic dynamic pack")
from winre import casepack
src = td / "pack"
(src / "dynamic").mkdir(parents=True, exist_ok=True)
(src / "dynamic" / "META.json").write_text(json.dumps(
    {"ok": True, "started_at": "2026-09-07T11:00:00Z",
     "finished_at": "2026-09-07T11:01:00Z", "frida_events": 5}))
(src / "dynamic" / "frida_trace.jsonl").write_text("{}")
(src / "audit.json").write_text(json.dumps({"truly_green": True}))
(src / "META.json").write_text(json.dumps({"mode": "static", "sha256": "x" * 64}))
cp = casepack.build_case(src, "x" * 64, "static")
check("casepack_ok", cp.get("ok") is True, str(cp.get("error")))
check("casepack_7z", cp.get("suffix") == ".7z", str(cp.get("path")))
if cp.get("ok"):
    check("casepack_manifest_inside", (Path(cp["path"]).stat().st_size > 0))

print("[10] pcap_beacon — tshark availability (host) marked, VM-verified")
try:
    from winre import pcap_beacon
    check("tshark_on_host", pcap_beacon._tshark() is not None,
          "VM smoke covers tshark path")
except Exception as e:
    check("pcap_beacon_import", False, str(e))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} — {FAILS}")
    sys.exit(1)
print("ALL HOST TESTS PASSED")