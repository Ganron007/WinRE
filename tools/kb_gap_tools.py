#!/usr/bin/env python3
"""kb_gap_tools.py — KB-derived static gap tools (G:\\doc_extract review, 2026-09-07).

Pure-python (pefile where possible), all tolerant of absence, all bounded.
Implements the recorded static gaps:

  crypto_constants   - magic constants + AES S-box scan (findcrypt equivalent;
                       KB AMAT Track 4: crypto recognition by constants+shape)
  mitigations        - PE hardening/mitigation catalog (revai_tools_sec port)
  sink_sites         - dangerous-API call sites in functions, r2-assisted
                       (revai_tools_sinks/audit port, bounded)
  rtf_predecode      - RTF container decode BEFORE olevba (AMAT Tracks 9-12)
  string_decode_emulate - event-driven light emulation of decrypt/decoder calls
                       (AMAT Track 6 / FLARE encStrings); yields config-level
                       candidates = the config-extractor deliverable seed
  rolling_xor        - multi-byte + date-seeded XOR keys, known-plaintext
                       guided (Maldev 77, Z2A Qakbot date-seeded XOR)
  script_decode      - script-stage deobfuscation: base64/deflate layers,
                       FromCharCode chains, -enc payloads, embedded PE/shellcode
                       (Script-Based Malware Analysis; MOS AMSI angles)
  ioc_extract        - wallet addresses + defanged URLs/domains/IPs/emails
                       (revai_tools_iocs port; hashes are IOCs)
  goresym_analyze    - Go binary symbol recovery wrapper (goresym on VM)
  api_hash_resolver  - (imported from flare_static_tools; kept here for CLI)

CLI: python kb_gap_tools.py <tool> <sample> [--json]
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

PY = sys.executable or r"C:\Python313\python.exe"
R2 = r"C:\Tools\radare2\radare2.exe"


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"not found: {cmd[0]}"


def _skipped(tool: str, detail: str = "") -> dict:
    return {"ok": False, "skipped": f"{tool}: {detail or 'not available'}"}


def _exe_sections_bytes(sample: str, cap: int = 64 * 1024 * 1024) -> tuple[bytes, list]:
    """Concatenated executable-section raw bytes + section info (pefile)."""
    import pefile
    pe = pefile.PE(sample, fast_load=True)
    secs = []
    blob = b""
    for s in pe.sections:
        info = {"name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                "va": s.VirtualAddress, "size": s.Misc_VirtualSize,
                "entropy": round(s.get_entropy(), 2),
                "exec": bool(s.Characteristics & 0x20000000)}
        secs.append(info)
        if info["exec"] and len(blob) < cap:
            blob += (s.get_data() or b"")
    pe.close()
    return blob, secs


def _scan_u32(hay: bytes, needle: int) -> int:
    """Count occurrences of a little-endian u32 constant in bytes."""
    n = struct.pack("<I", needle & 0xFFFFFFFF)
    return hay.count(n)


# ── crypto_constants (findcrypt-class, constants+shape) ─────────────────────

_CRYPTO_MAGICS: dict[int, str] = {
    0x9E3779B9: "TEA/XTEA/RC5-Q32 delta",
    0x61C88647: "TEA/XORSHIFT-family (delta-2)",
    0xB7E15163: "RC5 P32 / Blowfish P-array seed",
    0x67452301: "MD5/SHA1 init A",
    0xEFCDAB89: "MD5/SHA1 init B",
    0x98BADCFE: "MD5/SHA1 init C",
    0x10325476: "MD5 init D",
    0xC3D2E1F0: "SHA1 init E",
    0x428A2F98: "SHA256 K[0]",
    0x71374491: "SHA256 K[1]",
    0x5A827999: "SHA1 K0 (0x5A827999)",
    0x6ED9EBA1: "SHA1 K1",
    0x8F1BBCDC: "SHA1 K2",
    0xCA62C1D6: "SHA1 K3",
    0xEDB88320: "CRC32 polynomial (reflected)",
    0x04C11DB7: "CRC32 polynomial (normal)",
    0x01000193: "FNV prime (32)",
    0x811C9DC5: "FNV offset basis",
    0xCC9E2D51: "Murmur3 c1",
    0x1B873593: "Murmur3 c2",
    0x5BD1E995: "Murmur2 m",
    0x9747B28C: "Murmur2 seed (SDBM-ish family)",
    0x6A09E667: "SHA512/SHA256 init (big-endian A)",
    0xBB67AE85: "SHA512 init B",
    0x3C6EF372: "SHA512 init C",
    0xA54FF53A: "SHA512 init D",
    0x510E527F: "SHA512 init E",
    0x9B05688C: "SHA512 init F",
    0x1F83D9AB: "SHA512 init G",
    0x5BE0CD19: "SHA512 init H",
    0x6A09E667F3BCC909 >> 0: "SHA256 init A (LE)",
    0x2F693070: "custom AES/MD5 mix (OALabs patterns)",
}

_AES_SBOX = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
])


def crypto_constants(sample: str, timeout: int = 300) -> dict:
    """FindCrypt-class scan: crypto magic constants + AES S-box presence."""
    t0 = time.time()
    try:
        blob, secs = _exe_sections_bytes(sample)
    except Exception as e:
        return {"ok": False, "error": f"crypto_constants: {e}",
                "tool": "crypto_constants"}
    hits = []
    for const, label in _CRYPTO_MAGICS.items():
        n = _scan_u32(blob, const)
        if n:
            hits.append({"constant": hex(const), "algo": label,
                         "occurrences": n})
    sbox = _AES_SBOX
    if sbox in blob or bytes(reversed(_AES_SBOX[:64])) in blob:
        hits.append({"constant": "aes-sbox", "algo": "AES S-box table",
                     "occurrences": 1})
    hits.sort(key=lambda h: -h["occurrences"])
    return {
        "ok": True, "tool": "crypto_constants",
        "duration_s": round(time.time() - t0, 2),
        "sections": secs,
        "hits": hits[:25],
        "crypto_identified": sorted({h["algo"] for h in hits}),
        "hint": ("Crypto constants found in executable sections: "
                 "config/keys may be recoverable." if hits else
                 "No crypto magic constants found (may still use homebrew "
                 "XOR/SUB/ADD crypto — see xor_string_search)."),
    }


# ── mitigations (revai_tools_sec port) ──────────────────────────────────────

def mitigations(sample: str, timeout: int = 120) -> dict:
    """PE mitigation/hardening catalog (sec-equivalent, deterministic)."""
    t0 = time.time()
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        flags = {
            "ASLR": bool(dc & 0x40),
            "DEP/NX": bool(dc & 0x100),
            "SEH-stripped": bool(dc & 0x400),
            "force-integrity": bool(dc & 0x80),
            "guard-CF": bool(dc & 0x4000),
            "high-entropy-va": bool(dc & 0x20),
            "appcontainer": bool(dc & 0x1000),
            "no-isolation": bool(dc & 0x200),
            "no-seh": bool(dc & 0x400),
        }
        major_os = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        min_stack = pe.OPTIONAL_HEADER.SizeOfStackCommit
        has_gs = any("__security_cookie" in str(getattr(fn, "name", b""))
                     for fn in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
                     for fn2 in (getattr(fn, "imports", []) or [])
                     for fn3 in [fn2])
        pe.close()
        return {
            "ok": True, "tool": "mitigations",
            "duration_s": round(time.time() - t0, 2),
            "dll_characteristics": hex(dc),
            "flags": flags,
            "os_major": major_os,
            "stack_commit": min_stack,
            "hint": ("Mitigation catalog — low ASLR/DEP coverage is common in "
                     "packed/legacy malware and is a (weak) evasion-pipeline "
                     "signal, not a verdict driver."),
        }
    except Exception as e:
        return {"ok": False, "error": f"mitigations: {e}",
                "tool": "mitigations"}


# ── RTF pre-decode (before olevba) ──────────────────────────────────────────

_RTF_CTL = re.compile(rb"\\([a-z]+)(-?\d+)? ?", re.I)


def rtf_predecode(sample: str, timeout: int = 120) -> dict:
    """RTF container decode: control words, hex escapes, \\bin blocks, OLE2.

    KB: RTF is the container — decode it BEFORE olevba/peepdf. When embedded
    OLE2 objects are found, the caller runs olevba against the extracted blob.
    """
    t0 = time.time()
    try:
        data = Path(sample).read_bytes()[:8 * 1024 * 1024]
    except OSError as e:
        return {"ok": False, "error": f"rtf_predecode: {e}"}
    if not data.lstrip().startswith(b"{\\rtf"):
        return {"ok": True, "tool": "rtf_predecode", "is_rtf": False,
                "note": "not an RTF container"}

    hex_blocks = re.findall(rb"\\'([0-9a-fA-F]{2})", data)
    unicode_esc = re.findall(rb"\\u(-?\d+)", data)
    bin_blocks = re.findall(rb"\\bin(\d+)", data)
    decoded_hex = bytes(int(h, 16) for h in hex_blocks[:2000])
    # \objdata\bin<len> ... — extract the OLE2 blob if present
    ole_blobs: list[bytes] = []
    for m in re.finditer(rb"\\objdata\\bin(-?\d+)\s*", data):
        try:
            n = int(m.group(1))
        except ValueError:
            continue
        blob = data[m.end():m.end() + max(n, 0)]
        if blob[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            ole_blobs.append(blob)
    return {
        "ok": True, "tool": "rtf_predecode", "is_rtf": True,
        "duration_s": round(time.time() - t0, 2),
        "hex_escape_count": len(hex_blocks),
        "unicode_escape_count": len(unicode_esc),
        "bin_block_count": len(bin_blocks),
        "embedded_ole2": bool(ole_blobs),
        "ole2_blob_count": len(ole_blobs),
        "decoded_hex_sample": decoded_hex[:256].hex(),
        "embedded_ole2_paths": [],
        "hint": ("RTF decoded: run olevba on embedded OLE2 when present; "
                 "hex/unicode escapes often hide C2/mutex strings." if ole_blobs
                 else "RTF decoded; no embedded OLE2 objects."),
    }


# ── string_decode_emulate (light emulation of decrypt calls) ────────────────

def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(b)


def _decode_with(blob: bytes, key: bytes, mode: str) -> bytes:
    if mode == "xor":
        return bytes((b ^ key[i % len(key)]) for i, b in enumerate(blob))
    if mode == "add":
        return bytes((b + key[i % len(key)]) & 0xFF for i, b in enumerate(blob))
    if mode == "sub":
        return bytes((b - key[i % len(key)]) & 0xFF for i, b in enumerate(blob))
    if mode == "rol":
        return bytes(((b << (key[i % len(key)] & 7)) |
                      (b >> (8 - (key[i % len(key)] & 7)))) & 0xFF
                     for i, b in enumerate(blob))
    return blob


def _find_strings(dec: bytes, min_len: int = 5) -> list[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, dec):
        s = m.group(0).decode("ascii", "ignore")
        if s not in out:
            out.append(s)
    return out


def _candidate_keys(data: bytes, sample: str | None = None,
                    timeout: int = 120) -> list[tuple[str, bytes]]:
    """Candidate decoder keys: nibble bytes, multi-byte, date-seeded."""
    keys: list[tuple[str, bytes]] = []
    for k in range(1, 256):
        keys.append(("xor", bytes([k])))
        keys.append(("add", bytes([k])))
        keys.append(("sub", bytes([k])))
    for k in range(0, 256, 1):
        keys.append(("rol", bytes([k])))
    # multi-byte (16-bit keys, common for URL encoders)
    for k in (0x1234, 0x4321, 0xABCD, 0xCDAB, 0x5A5A, 0x69, 0x55AA):
        keys.append(("xor", struct.pack("<H", k)))
    # date-seeded (yyyyMMdd / yyMMdd around compile time / current)
    seeds = set()
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        ts = pe.FILE_HEADER.TimeDateStamp
        import datetime
        seeds.add(datetime.datetime.utcfromtimestamp(ts).strftime("%Y%m%d"))
        seeds.add(datetime.datetime.utcfromtimestamp(ts).strftime("%y%m%d"))
        pe.close()
    except Exception:
        pass
    now = time.gmtime()
    seeds.add(time.strftime("%Y%m%d", now))
    seeds.add(time.strftime("%y%m%d", now))
    for s in seeds:
        keys.append(("xor", s.encode()))
        keys.append(("add", s.encode()))
    return keys


def string_decode_emulate(sample: str, timeout: int = 300) -> dict:
    """Event-driven light emulation: locate likely-encoded config blobs and
    decode with candidate keys (xor/add/sub/rol, 1-2 byte + date-seeded).

    KB AMAT Track 6 / FLARE encStrings: find address tables that reference
    data inside high-entropy sections, decode those blobs, recover plaintext
    config. This is the bounded, deterministic approximation: entropy-guided
    blob selection + key search + known-plaintext scoring.
    """
    t0 = time.time()
    try:
        data = Path(sample).read_bytes()
    except OSError as e:
        return {"ok": False, "error": f"string_decode_emulate: {e}"}
    try:
        blob, secs = _exe_sections_bytes(sample, cap=32 * 1024 * 1024)
    except Exception as e:
        return {"ok": False, "error": f"string_decode_emulate: {e}"}

    high_ent = [s for s in secs if s["entropy"] >= 6.5]
    # fall back to whole-file scanning when no exec sections
    if not high_ent:
        high_ent = [{"name": "whole", "entropy": 7.0, "exec": True}]
    # chunk the exec blob at 512-byte windows, keep high-entropy windows
    candidates: list[bytes] = []
    step, win = 256, 1024
    idx = 0
    while idx + win <= len(blob) and len(candidates) < 24:
        chunk = blob[idx:idx + win]
        import math
        if chunk:
            counts = [0] * 256
            for b in chunk:
                counts[b] += 1
            ent = -sum((c / len(chunk)) * math.log2(c / len(chunk))
                       for c in counts if c)
            if ent >= 6.8:
                candidates.append(chunk)
        idx += step
    if not candidates:
        return {"ok": True, "tool": "string_decode_emulate",
                "decoded": [], "note": "no high-entropy windows found"}

    decoded: list[dict] = []
    for blob_n in candidates:
        best: dict | None = None
        for mode, key in _candidate_keys(blob_n, sample):
            dec = _decode_with(blob_n, key, mode)
            ratio = _printable_ratio(dec)
            strs = _find_strings(dec, min_len=6)
            if ratio >= 0.55 and len(strs) >= 2 and len(decoded) < 40:
                score = ratio * 10 + min(len(strs), 10)
                cand = {"mode": mode, "key": key.hex(),
                        "ratio": round(ratio, 2), "strings": strs[:10],
                        "score": round(score, 1)}
                if best is None or score > best["score"]:
                    best = cand
        if best:
            decoded.append(best)
    decoded.sort(key=lambda d: -d["score"])
    return {
        "ok": True, "tool": "string_decode_emulate",
        "duration_s": round(time.time() - t0, 2),
        "sections_scanned": len(secs),
        "candidate_blobs": len(candidates),
        "decoded_blobs": len(decoded),
        "decoded": decoded[:10],
        "hint": ("Encoded config candidates recovered. Treat as CONFIG "
                 "EXTRACTOR seed: verify against dynamic behavior before "
                 "trusting." if decoded else
                 "No high-confidence encoded config recovered; sample may "
                 "decrypt at runtime only."),
    }


# ── rolling_xor (multi-byte + date-seeded, known-plaintext guided) ─────────

_PE_MAGIC = b"MZ"


def rolling_xor(sample: str, timeout: int = 300) -> dict:
    """Rolling/date-seeded XOR search (Maldev 77, Z2A Qakbot).

    Multi-byte keys via known-plaintext guidance: a nested PE (MZ header)
    or repeated 'This program cannot be run in DOS mode' inside a payload
    fixes the key prefix; date-seeded keys from compile time are tried.
    """
    t0 = time.time()
    try:
        data = Path(sample).read_bytes()
    except OSError as e:
        return {"ok": False, "error": f"rolling_xor: {e}"}
    found: list[dict] = []
    # 1) PE-in-PE: for each position, derive key bytes that would map the
    #    bytes to 'MZ\x90\x00' plaintext, then VALIDATE byte 4 (0x03 = COFF
    #    Machine field little-endian start) and that further decrypted bytes
    #    look like a PE header (printable-ish + zero runs).
    for pos in range(64, min(len(data) - 8, 8 * 1024 * 1024)):
        k1 = data[pos] ^ 0x4D  # 'M'
        k2 = data[pos + 1] ^ 0x5A  # 'Z'
        # accept single-byte keys (k1==k2) or 2-byte keys; validate 0x90 and 0x00
        if (k1 == k2 and data[pos + 2] ^ k1 in (0x90, 0x00, 0x50, 0x20)
                and data[pos + 3] ^ k1 == 0x00) or \
           (k1 != k2 and data[pos + 2] ^ k1 in (0x90, 0x00)
                and data[pos + 3] ^ k2 == 0x00):
            # bonus check: bytes 4-5 of a PE header are 0x03 0x00 (COFF)
            k = k1 if k1 == k2 else None
            if k is None:
                k = (k1, k2)
            try:
                b4 = data[pos + 4] ^ (k if isinstance(k, int) else k[0])
                b5 = data[pos + 5] ^ (k if isinstance(k, int) else k[1])
            except IndexError:
                continue
            if b4 == 0x03 and b5 == 0x00:
                found.append({
                    "kind": "pe-in-pe", "offset": pos,
                    "key": (bytes([k]) if isinstance(k, int)
                            else bytes(k)).hex(),
                    "note": "PE-in-PE: derived key maps header bytes to "
                            "MZ\\x90\\x00 + COFF 0x03 0x00"})
                break
    # 2) date-seeded: XOR payload with compile-date keys, look for PE or URLs
    keys: list[tuple[str, bytes]] = []
    import datetime
    now = datetime.datetime.utcnow()
    keys.append(("xor", now.strftime("%Y%m%d").encode()))
    keys.append(("xor", now.strftime("%y%m%d").encode()))
    for blob_n in (data[-max(4, len(data) // 4):], data[:max(4, len(data) // 4)]):
        for name, key in keys:
            dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob_n))
            if _PE_MAGIC in dec[:512] or b"http" in dec[:4096]:
                found.append({"kind": "date-seeded", "key_name": name,
                              "key": key.hex(),
                              "plaintext_head": dec[:128].hex()})
    return {
        "ok": True, "tool": "rolling_xor",
        "duration_s": round(time.time() - t0, 2),
        "results": found[:8],
        "hint": ("Rolling/date-seeded XOR key candidates found." if found else
                 "No known-plaintext-guided rolling-XOR key recovered."),
    }


# ── script_decode (script-stage deobfuscation) ──────────────────────────────

_B64_RE = re.compile(rb"[A-Za-z0-9+/=]{60,}")


def _try_b64_deflate(s: bytes) -> bytes | None:
    try:
        raw = base64.b64decode(s.strip(), validate=False)
        return zlib.decompress(raw)
    except Exception:
        return None


def _fromcharcode_decode(s: bytes) -> str | None:
    m = re.search(rb"fromCharCode\s*\(\s*([0-9,\s]+)\s*\)", s, re.I)
    if not m:
        return None
    try:
        nums = [int(x) for x in m.group(1).split(b",") if x.strip()]
        return "".join(chr(n) for n in nums if 0 < n < 0x110000)
    except ValueError:
        return None


def script_decode(sample: str, timeout: int = 180) -> dict:
    """Script-stage deobfuscation: base64/deflate layers, FromCharCode,
    -enc encoded PS, embedded PE/shellcode inside scripts."""
    t0 = time.time()
    try:
        data = Path(sample).read_bytes()[:16 * 1024 * 1024]
    except OSError as e:
        return {"ok": False, "error": f"script_decode: {e}"}
    layers: list[dict] = []
    cur = data
    for _ in range(4):
        nxt = None
        kind = None
        # base64 (possibly deflated)
        for m in _B64_RE.finditer(cur):
            dec = _try_b64_deflate(m.group(0))
            if dec and len(dec) > 16:
                nxt, kind = dec, "base64+deflate"
                break
        if nxt is None:
            # FromCharCode chains
            s = _fromcharcode_decode(cur)
            if s and len(s) > 16:
                nxt, kind = s.encode("utf-8", "ignore"), "fromcharcode"
        if nxt is None or nxt == cur:
            break
        layers.append({"layer": len(layers) + 1, "kind": kind,
                       "size": len(nxt)})
        cur = nxt

    embedded = {
        "pe": bool(_PE_MAGIC in cur[:4096]) or _PE_MAGIC in cur[-64:],
        "shellcode": bool(re.search(rb"\xfc[\x48\xe8][\x8b\x89]\x0c", cur)),
        "urls": [u.decode("ascii", "ignore") for u in
                 re.findall(rb"https?://[^\s\"']{8,120}", cur)[:5]],
    }
    return {
        "ok": True, "tool": "script_decode",
        "duration_s": round(time.time() - t0, 2),
        "is_script_like": bool(layers) or embedded["pe"] or embedded["shellcode"],
        "layers": layers,
        "embedded": embedded,
        "hint": ("Script-stage payload decoded (base64/deflate/fromcharcode "
                 "layers); embedded PE/shellcode flagged for sandboxing." if
                 (layers or embedded["pe"] or embedded["shellcode"]) else
                 "No script-stage encoding detected."),
    }


# ── ioc_extract (revai_tools_iocs port: wallets + defanged) ─────────────────

_WALLET_RE = {
    "btc": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "xmr": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "ltc": re.compile(r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b"),
}
_DEFANGED_URL = re.compile(r"hxxp[s]?://[^\s\"'<>]{6,200}", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                     r"(?:com|net|org|info|biz|ru|cn|top|xyz|cc|io|onion)\b", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)


def ioc_extract(sample: str, timeout: int = 180) -> dict:
    """IOC extraction: wallets + defanged URLs + domains/IPs/emails."""
    t0 = time.time()
    try:
        data = Path(sample).read_bytes()[:32 * 1024 * 1024]
    except OSError as e:
        return {"ok": False, "error": f"ioc_extract: {e}"}
    text = data.decode("utf-8", "replace")
    out: dict = {"wallets": {}, "urls": [], "domains": [], "ips": [],
                 "emails": []}
    for kind, rx in _WALLET_RE.items():
        hits = list(dict.fromkeys(rx.findall(text)))
        if hits:
            out["wallets"][kind] = hits[:20]
    for u in dict.fromkeys(_DEFANGED_URL.findall(text)):
        out["urls"].append(u.replace("hxxp", "http", 1) if u.lower().startswith("hxxp") else u)
    out["domains"] = list(dict.fromkeys(_DOMAIN.findall(text)))[:40]
    ips = [ip for ip in dict.fromkeys(_IPV4.findall(text))
           if not ip.startswith(("127.", "0.", "255.")) and ip != "0.0.0.0"]
    out["ips"] = ips[:40]
    out["emails"] = list(dict.fromkeys(_EMAIL.findall(text)))[:20]
    out["total"] = sum(len(v) if isinstance(v, list) else sum(len(x) for x in v.values())
                       for v in out.values() if v)
    return {"ok": True, "tool": "ioc_extract",
            "duration_s": round(time.time() - t0, 2), **out}


# ── goresym_analyze ─────────────────────────────────────────────────────────

def _is_go(data: bytes) -> bool:
    return (b"Go build ID" in data[:2 * 1024 * 1024]
            or b"go1." in data[:2 * 1024 * 1024]
            or b"runtime.main" in data[:8 * 1024 * 1024])


def goresym_analyze(sample: str, timeout: int = 300) -> dict:
    """Go binary symbol recovery (goresym on VM). Format-gated: only runs
    when Go markers are present (honest skip otherwise)."""
    t0 = time.time()
    try:
        data = Path(sample).read_bytes()[:8 * 1024 * 1024]
    except OSError as e:
        return {"ok": False, "error": f"goresym_analyze: {e}"}
    if not _is_go(data):
        return {"ok": True, "tool": "goresym_analyze", "is_go": False,
                "note": "not a Go binary"}
    exe = None
    for cand in (r"C:\Tools\goresym\goresym.exe",
                 r"C:\Tools\goresym\goresym_amd64.exe"):
        if Path(cand).is_file():
            exe = cand
            break
    if not exe:
        return _skipped("goresym_analyze", "goresym not installed")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="winre-go-") as td:
        out_json = Path(td) / "out.json"
        # goresym CLI: <exe> [PE|Mach-O|ELF] <input> <output>
        rc, out, err = _run([exe, "PE", sample, str(out_json)], timeout)
        if rc != 0:
            return {"ok": False, "error": (err or out)[-250:],
                    "tool": "goresym_analyze"}
        if not out_json.is_file():
            return {"ok": False, "error": "goresym produced no output",
                    "tool": "goresym_analyze"}
        try:
            d = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            d = {"raw_head": out_json.read_text(
                encoding="utf-8", errors="replace")[:2000]}
        funcs = d.get("UserFunctions") or d.get("functions") or []
        bi = d.get("BuildInfo") if isinstance(d, dict) else None
        if not isinstance(bi, dict):
            bi = d.get("buildInfo") if isinstance(d, dict) else {}
        if not isinstance(bi, dict):
            bi = {}
        return {
            "ok": True, "tool": "goresym_analyze", "is_go": True,
            "duration_s": round(time.time() - t0, 2),
            "build_info": bi,
            "go_version": bi.get("GoVersion"),
            "user_functions": [f.get("FunctionName") for f in funcs[:60]
                               if isinstance(f, dict)],
            "function_count": len(funcs) if isinstance(funcs, list) else 0,
            "hint": "Go symbols recovered — function names are capability "
                    "evidence + YARA meta.",
        }


# ── sink_sites (revai_tools_sinks/audit port, r2-assisted) ─────────────────

_SINK_APIS = (
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
    "NtUnmapViewOfSection", "SetThreadContext", "QueueUserAPC",
    "CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteA",
    "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW",
    "RegSetValueExA", "RegSetValueExW", "CryptEncrypt", "CryptDecrypt",
    "InternetOpenA", "InternetOpenW", "WSAStartup", "send", "recv",
    "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW",
)


def sink_sites(sample: str, timeout: int = 300) -> dict:
    """Dangerous-API call sites in named functions (r2). Bounded:
    top-40 functions, sink list above; provenance = caller function."""
    t0 = time.time()
    r2 = Path(R2)
    if not r2.is_file():
        return _skipped("sink_sites", "radare2 not installed")
    try:
        size = Path(sample).stat().st_size
    except OSError:
        size = 0
    # full analysis first (packed binaries need aaa; light aa as fallback).
    # aaa is bounded by the timeout and skipped for huge files.
    analyze_cmd = "aaa" if size < 40 * 1024 * 1024 else "aa"
    rc, out, err = _run([str(r2), "-2", "-q", "-c",
                         f"{analyze_cmd};aflj", sample],
                        min(timeout, 240))
    if rc != 0:
        return {"ok": False, "error": (err or out)[-250:],
                "tool": "sink_sites"}
    try:
        funcs = json.loads(out)
    except json.JSONDecodeError:
        funcs = []
    if not isinstance(funcs, list):
        funcs = []
    if not funcs:
        # light re-analysis attempt: aa then aflj
        rc2, out2, _ = _run([str(r2), "-2", "-q", "-c", "aa;aflj", sample],
                            min(timeout, 120))
        if rc2 == 0:
            try:
                funcs = json.loads(out2) or []
            except json.JSONDecodeError:
                funcs = []
    if not isinstance(funcs, list):
        funcs = []
    top = sorted(funcs, key=lambda f: f.get("size", 0), reverse=True)[:40]
    sites: list[dict] = []
    # disassemble each and look for calls to the sink imports
    for f in top:
        addr = f.get("offset")
        name = f.get("name", f"f_{addr:x}")
        rc2, out2, _ = _run(
            [str(r2), "-2", "-q", "-c", f"pd 200 @ {addr}", sample],
            min(timeout, 60))
        if rc2 != 0:
            continue
        for line in (out2 or "").splitlines():
            for api in _SINK_APIS:
                if f"sym.imp.{api}" in line or f"imp.{api}" in line:
                    sites.append({"function": name, "address": hex(addr),
                                  "api": api})
                    break
    # dedupe + cap
    seen: set = set()
    uniq = []
    for s in sites:
        k = (s["function"], s["api"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(s)
        if len(uniq) >= 60:
            break
    return {
        "ok": True, "tool": "sink_sites",
        "duration_s": round(time.time() - t0, 2),
        "functions_scanned": len(top),
        "sites": uniq,
        "sink_api_hits": sorted({s["api"] for s in uniq}),
        "hint": ("Dangerous-API call sites with provenance (caller function). "
                 "Feed to report section 'sinks'." if uniq else
                 "No sink calls found in scanned functions."),
    }


# ── decrypt_gate (AMAT Track 7: is the sample analysis-ready?) ─────────────

def decrypt_gate(sample: str, timeout: int = 300) -> dict:
    """Analysis-readiness gate: import-stripped + sparse strings + packer
    taxonomy (compression vs encryption vs virtualization).

    status="clear": static tools are trustworthy.
    status="gate":  imports/strings/code are encrypted or packed — capa and
    string-derived evidence is UNRELIABLE; verdict must not lean on it.
    """
    t0 = time.time()
    import math
    try:
        import pefile
        pe = pefile.PE(sample, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        imp_count = sum(len(getattr(entry, "imports", []) or [])
                        for entry in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []))
        imp_dlls = [entry.dll.decode("ascii", "replace")
                    for entry in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])]
        secs = []
        for s in pe.sections:
            secs.append({"name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                         "size": s.Misc_VirtualSize,
                         "entropy": round(s.get_entropy(), 2),
                         "exec": bool(s.Characteristics & 0x20000000)})
        size = pe.OPTIONAL_HEADER.SizeOfImage
        pe.close()
    except Exception as e:
        return {"ok": False, "error": f"decrypt_gate: {e}"}

    high_ent = [s for s in secs if s["entropy"] >= 7.0]
    # strings sparsity: printable-run coverage over exec sections
    try:
        data = Path(sample).read_bytes()
    except OSError:
        data = b""
    printable = sum(1 for c in data[:16 * 1024 * 1024] if 32 <= c < 127)
    str_ratio = printable / max(len(data[:16 * 1024 * 1024]), 1)
    sparse_strings = str_ratio < 0.35 and size > 8192

    # packer taxonomy from diec labels when available
    taxonomy = "none"
    try:
        from flare_static_tools import diec as _diec
        d = _diec(sample, timeout=min(timeout, 120))
        labels = " ".join(str(x).lower() for x in (d.get("detects") or []))
        if any(k in labels for k in ("vmprotect", "themida", "vmp", "virtualiz")):
            taxonomy = "virtualization"
        elif any(k in labels for k in ("packer", "packed", "aspack", "upx",
                                       "mpress", "molebox", "enigma")):
            taxonomy = "compression"
        elif any(k in labels for k in ("encrypt", "cryptor", "crypter",
                                       "protector", "obfus")):
            taxonomy = "encryption"
    except Exception:
        labels = ""

    gated = (imp_count <= 2 and sparse_strings) or (high_ent and sparse_strings)
    return {
        "ok": True, "tool": "decrypt_gate",
        "duration_s": round(time.time() - t0, 2),
        "status": "gate" if gated else "clear",
        "taxonomy": taxonomy,
        "import_count": imp_count,
        "import_dlls": imp_dlls[:8],
        "string_ratio": round(str_ratio, 3),
        "sparse_strings": sparse_strings,
        "high_entropy_sections": [s["name"] for s in high_ent],
        "packer_labels": labels.split()[:6],
        "hint": ("GATED: imports/strings/code encrypted or packed — capa and "
                 "string evidence unreliable; unpack/decrypt before deep "
                 "static conclusions (AMAT Track 7)." if gated else
                 "CLEAR: static evidence is trustworthy."),
    }


# ── dispatch ────────────────────────────────────────────────────────────────

TOOL_FUNCS = {
    "crypto_constants": crypto_constants,
    "mitigations": mitigations,
    "rtf_predecode": rtf_predecode,
    "string_decode_emulate": string_decode_emulate,
    "rolling_xor": rolling_xor,
    "script_decode": script_decode,
    "ioc_extract": ioc_extract,
    "goresym_analyze": goresym_analyze,
    "sink_sites": sink_sites,
    "decrypt_gate": decrypt_gate,
}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="KB-derived static gap tools")
    ap.add_argument("tool", choices=list(TOOL_FUNCS.keys()))
    ap.add_argument("sample")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = TOOL_FUNCS[a.tool](a.sample)
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())