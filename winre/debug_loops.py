#!/usr/bin/env python3
r"""debug_loops.py — disciplined x64dbg debug loops (dynamic RE).

The x64dbg agentic debug loops, encoded as deterministic bounded functions so
the LangGraph agent and the dynamic phase can drive them reliably. Discipline
(from internal/IMPROVEMENT-PLAN.md P-A):

    - every `run` is followed by WaitForPause / state poll (never blind run)
    - bounded iteration counts (no infinite stub-walking)
    - state (regs + disasm@cip) captured after EVERY pause — evidence
    - redundant-hit detection: same RIP twice without progress -> stop
    - NEVER raw StepInto 5000x

Scenarios (each = one checklist item, test one-by-one):
    ep_break(sample)        LoadBinary -> run -> auto-EP break -> state   [1]
    oep_by_section(sample)  UPX/unpack: mem-BP on original .text exec
                            region -> run -> OEP break -> dump            [2]
    wpm_dump(sample)        BP WriteProcessMemory -> run -> on hit, decode
                            x64 args (rcx,rdx,r8,r9), ReadMemory src buf,
                            dump it -> bounded hits                      [3]
    api_loop(sample, api)   BP on API (e.g. CryptDecrypt) -> run ->
                            capture args on hit -> bounded hits           [4]
    agentic_unpack(sample)  OEP -> DumpModule -> static re-analysis of the
                            dump -> compare original vs unpacked verdict [5]

All return {"ok", "evidence": {...}, "error"} — evidence is the LLM-usable
record of every pause (rip, regs, disasm).
"""
from __future__ import annotations

import re
import time
from typing import Any

from winre.mcp import X64DbgClient


def _state_text(st: dict) -> str:
    res = st.get("result") or {}
    if isinstance(res, dict) and res.get("content"):
        c = res["content"]
        if isinstance(c, list) and c:
            return c[0].get("text", "")
    return ""


def _parse_state(st: dict) -> dict:
    txt = _state_text(st)
    out: dict = {}
    for key in ("isDebugging", "isRunning", "status", "currentAddress",
                "currentModule", "stackPointer", "pid"):
        m = re.search(rf"{key}: (\S+)", txt)
        if m:
            out[key] = m.group(1)
    return out


def _rip(xc: X64DbgClient) -> int | None:
    st = _parse_state(xc.get_state())
    try:
        return int(st.get("currentAddress", ""), 16)
    except ValueError:
        return None


def _disasm(xc: X64DbgClient, addr: int | None, count: int = 6) -> str:
    if addr is None:
        return ""
    d = xc.disassemble_at(addr, count=count)
    res = d.get("result") or {}
    if isinstance(res, dict) and res.get("content"):
        c = res["content"]
        if isinstance(c, list) and c:
            return c[0].get("text", "")
    return ""


def _regs(xc: X64DbgClient) -> str:
    r = xc.get_all_registers()
    res = r.get("result") or {}
    if isinstance(res, dict) and res.get("content"):
        c = res["content"]
        if isinstance(c, list) and c:
            return c[0].get("text", "")
    return ""


def _bp_text(xc: X64DbgClient) -> str:
    lb = xc.list_breakpoints()
    lr = lb.get("result") or {}
    lc = lr.get("content") or [{}]
    return lc[0].get("text", "") if isinstance(lc, list) else ""


def _pause_evidence(xc: X64DbgClient, label: str, rip: int | None) -> dict:
    return {
        "label": label,
        "rip": hex(rip) if rip else None,
        "regs": _regs(xc)[:800],
        "disasm": _disasm(xc, rip) if rip else "",
    }


# ---------------------------------------------------------------------------
# Scenario 1 — EP break smoke
# ---------------------------------------------------------------------------
def ep_break(sample: str, xc: X64DbgClient | None = None,
             max_wait_s: int = 40) -> dict:
    """LoadBinary -> run -> pause at EP (x64dbg auto-EP-breaks)."""
    xc = xc or X64DbgClient()
    evidence: list[dict] = []
    # x64dbg persists breakpoints across LoadBinary sessions — always start clean
    try:
        xc.call("DeleteAllBreakpoints")
    except Exception:
        pass
    r = xc.load_binary(sample)
    if not r.get("ok"):
        return {"ok": False, "error": f"load failed: {r.get('error')}",
                "evidence": evidence}
    time.sleep(2)
    xc.run()
    deadline = time.time() + max_wait_s
    rip = None
    while time.time() < deadline:
        time.sleep(2)
        rip = _rip(xc)
        st = _parse_state(xc.get_state())
        if st.get("isRunning") == "false" and st.get("status") == "LOCKED":
            break
    if rip is None:
        return {"ok": False, "error": "never paused", "evidence": evidence}
    evidence.append(_pause_evidence(xc, "ep_break", rip))
    return {"ok": True, "oep": rip, "evidence": evidence,
            "module": _parse_state(xc.get_state()).get("currentModule")}


# ---------------------------------------------------------------------------
# Scenario 2/3 — OEP via execute-BP on the original .text region (UPX etc)
# ---------------------------------------------------------------------------
def _module_base_and_sections(xc: X64DbgClient, sample_stem: str) -> tuple[int | None, list[dict]]:
    """Module base + sections from GetMemoryMap (format: start|size|perm|name).

    UPX-packed modules show UPX0/UPX1 sections — the original .text is
    decompressed into UPX0 (usually base+0x1000)."""
    mm = xc.get_memory_map()
    res = mm.get("result") or {}
    text = ""
    if isinstance(res.get("content"), list) and res.get("content"):
        text = res["content"][0].get("text", "")
    base = None
    sections: list[dict] = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            continue
        try:
            start = int(parts[0], 16)
        except ValueError:
            continue
        owner = parts[3]
        if sample_stem.lower() in owner.lower():
            if base is None:
                base = start  # header page (R--)
            sections.append({"start": start, "size": parts[1],
                             "perm": parts[2], "owner": owner})
    return base, sections


def oep_by_section(sample: str, xc: X64DbgClient | None = None,
                   text_offset: int = 0x1000, max_wait_s: int = 90) -> dict:
    """Unpack OEP via MEMORY-EXECUTE breakpoint on the unpack section.

    Method (analyst-standard, verified on UPX x64): EP break, find the
    unpack-target section (UPX0: the RWX region the stub decompresses into),
    set a memory-execute bp over it via raw `bpm start, size, x`, run.
    The FIRST instruction fetch in unpacked code is the OEP by definition.
    No stub-walking, no HW-BP DR-register dependence, no stack assumptions.
    """
    import os
    xc = xc or X64DbgClient()
    evidence: list[dict] = []
    stem = os.path.splitext(os.path.basename(sample))[0]
    r = ep_break(sample, xc)
    if not r.get("ok"):
        return r
    evidence.extend(r["evidence"])

    base, sections = _module_base_and_sections(xc, stem)
    if base is None:
        return {"ok": False, "error": "module base not found", "evidence": evidence}

    def _sz(s: dict) -> int:
        try:
            return int(str(s.get("size", "0")), 16)
        except ValueError:
            return 0

    # unpack target = UPX0-style section (RWX, after header) else first
    # executable section after the header page
    target, tsize = None, 0
    for s in sections:
        if s["start"] <= base:
            continue
        if "UPX0" in (s.get("owner") or "").upper():
            target, tsize = s["start"], _sz(s) or 0x10000
            break
    if target is None:
        execs = [s for s in sections if s["start"] > base
                 and "x" in (s.get("perm") or "").lower()]
        if execs:
            target, tsize = execs[0]["start"], _sz(execs[0]) or 0x10000
    if target is None:
        target, tsize = base + text_offset, 0x10000
    evidence.append({"label": "oep_membp_target",
                     "target": hex(target), "size": hex(tsize)})

    # memory-execute bp via raw debugger command (no HW-BP DR dependence)
    cmd = f"bpm {hex(target)}, {hex(tsize)}, x"
    cr = xc.execute_command(cmd)
    registered = hex(target).lower() in _bp_text(xc).lower()
    evidence.append({"label": "oep_membp_set", "cmd": cmd,
                     "ok": bool(cr.get("ok")), "registered": registered})
    if not registered:
        return {"ok": False,
                "error": f"memory bp {hex(target)} not registered",
                "evidence": evidence}

    xc.run()
    deadline = time.time() + max_wait_s
    rip = None
    while time.time() < deadline:
        time.sleep(2)
        rip = _rip(xc)
        st = _parse_state(xc.get_state())
        if st.get("isRunning") == "false":
            break
    if rip is None:
        return {"ok": False, "error": "never paused after membp run",
                "evidence": evidence}
    evidence.append(_pause_evidence(xc, "oep_membp_hit", rip))
    return {"ok": True, "oep": rip, "module_base": hex(base),
            "evidence": evidence}


# ---------------------------------------------------------------------------
# Scenario 2/3 — OEP via the ESP trick (classic UPX unpack method)
# ---------------------------------------------------------------------------
def oep_by_esp(sample: str, xc: X64DbgClient | None = None,
               max_wait_s: int = 90) -> dict:
    """Unpack OEP via the classic ESP trick (as x64dbg's own DetectOEP
    recommends): at the stub EP, set a HARDWARE bp on ESP/RSP. The stub's
    final ret/popad changes the stack pointer — the first instruction after
    that change is the OEP (unpacked code). Bounded wait; evidence per pause."""
    xc = xc or X64DbgClient()
    evidence: list[dict] = []
    r = ep_break(sample, xc)
    if not r.get("ok"):
        return r
    evidence.extend(r["evidence"])

    # read current RSP at the stub EP
    regs = _regs(xc)
    m = re.search(r"\brsp: (0x[0-9A-Fa-f]+)", regs, re.I)
    if not m:
        return {"ok": False, "error": "rsp not in regs", "evidence": evidence}
    esp = int(m.group(1), 16)
    evidence.append({"label": "esp_at_ep", "rsp": hex(esp)})

    # hardware bp on ESP (write) — fires when the stub adjusts the stack.
    # NOTE: the vendored plugin's SetHardwareBreakpoint returns ok but may
    # silently fail to register — always verify via ListBreakpoints.
    hw = xc.call("SetHardwareBreakpoint",
                 {"address": esp, "drIndex": 0, "type": "access"})
    if not hw.get("ok"):
        # fall back to default (execute) if access-type unsupported
        hw = xc.set_hw_breakpoint(esp, dr_index=0)
    bp_list = _bp_text(xc)
    registered = hex(esp).lower() in bp_list.lower()
    evidence.append({"label": "esp_hwbp", "ok": bool(hw.get("ok")),
                     "registered": registered})
    if not registered:
        return {"ok": False,
                "error": "hw bp did not register (plugin silent-drop); "
                         "software-bp fallback required",
                "evidence": evidence}

    xc.run()
    deadline = time.time() + max_wait_s
    rip = None
    while time.time() < deadline:
        time.sleep(2)
        st = _parse_state(xc.get_state())
        if st.get("isRunning") == "false":
            rip = _rip(xc)
            break
    if rip is None:
        return {"ok": False, "error": "never paused after ESP-bp run",
                "evidence": evidence}
    evidence.append(_pause_evidence(xc, "oep_esp_hit", rip))
    return {"ok": True, "oep": rip, "evidence": evidence,
            "module": _parse_state(xc.get_state()).get("currentModule")}


# ---------------------------------------------------------------------------
# Scenario 3 — WriteProcessMemory BP loop + buffer dump
# ---------------------------------------------------------------------------
def _parse_reg(regs: str, name: str) -> int | None:
    m = re.search(rf"\b{name}: (0x[0-9A-Fa-f]+)", regs, re.I)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None


def _read_buf(xc: X64DbgClient, addr: int, size: int) -> bytes:
    """Read target memory; the plugin may return hex text or base64."""
    r = xc.read_memory(addr, min(size, 65536))
    res = r.get("result") or {}
    content = res.get("content") if isinstance(res, dict) else None
    text = ""
    if isinstance(content, list) and content:
        text = content[0].get("text", "") or ""
    elif isinstance(content, str):
        text = content
    # try: raw hex dump lines ("  ADDR: bb bb ... <ascii>") -> bytes.
    # The ASCII column can start with hex-looking chars ("DE..."), so take
    # at most 16 whitespace-separated 2-char hex tokens per line (the plugin
    # prints 16 bytes/line) and stop at the first non-pair token.
    out = bytearray()
    for line in text.splitlines():
        m = re.match(r"\s*(?:0x)?[0-9A-Fa-f]+\s*:\s*(.*)", line)
        if not m:
            continue
        count = 0
        for tok in m.group(1).split():
            if count >= 16 or len(tok) != 2:
                break
            try:
                out.append(int(tok, 16))
                count += 1
            except ValueError:
                break
    if out:
        return bytes(out)
    # fall back: printable ASCII runs in the text
    return text.encode("utf-8", errors="replace")


    if out:
        return bytes(out)
    # fall back: printable ASCII runs in the text
    return text.encode("utf-8", errors="replace")


def _read_u64(xc: X64DbgClient, addr: int) -> int | None:
    """Read an 8-byte little-endian pointer from target memory."""
    buf = _read_buf(xc, addr, 8)
    if len(buf) < 8:
        return None
    return int.from_bytes(buf[:8], "little")


def _read_u32(xc: X64DbgClient, addr: int) -> int | None:
    """Read a 4-byte little-endian DWORD from target memory."""
    buf = _read_buf(xc, addr, 4)
    if len(buf) < 4:
        return None
    return int.from_bytes(buf[:4], "little")


def crypt_dump(sample: str, xc: X64DbgClient | None = None,
               max_hits: int = 2, max_wait_s: int = 60,
               dump_dir: str | None = None) -> dict:
    """BP CryptDecrypt -> on hit decode x64 args + stack args
    (rcx=hKey, rdx=hHash, r8=Final, r9=dwFlags, [rsp+0x28]=pbData,
    [rsp+0x30]=pdwDataLen), capture the CIPHERTEXT buffer, StepOut back to
    the caller, re-read the buffer as PLAINTEXT. Bounded hits.

    This is the crypto-unpack primitive: what malware decrypts in memory.
    """
    xc = xc or X64DbgClient()
    evidence: list[dict] = []
    # CryptDecrypt lives in advapi32/cryptsp, which is NOT mapped at load
    # time — setting the BP immediately would silently drop. Flow: load,
    # run (target executes its lead-in), wait until the crypto module is
    # mapped, THEN set the BP (test harnesses sleep first for this reason).
    try:
        xc.call("DeleteAllBreakpoints")
    except Exception:
        pass
    r = xc.load_binary(sample)
    if not r.get("ok"):
        return {"ok": False, "error": f"load failed: {r.get('error')}",
                "evidence": evidence}
    import time as _t
    _t.sleep(2)
    evidence.append({"label": "loaded", "sample": sample})

    xc.run()
    mod_found = False
    mod_deadline = time.time() + 60
    resumed_once = False
    while time.time() < mod_deadline:
        _t.sleep(2)
        mm = xc.get_memory_map()
        mr = mm.get("result") or {}
        mc = mr.get("content") or [{}]
        t = mc[0].get("text", "") if isinstance(mc, list) else ""
        if "cryptsp" in t.lower() or "advapi32" in t.lower():
            mod_found = True
            break
        st = _parse_state(xc.get_state())
        if st.get("isRunning") == "false" and not resumed_once:
            # paused at entry (native): DLLs are mapped now; resume so the
            # target proceeds toward the crypto call while we keep watching
            resumed_once = True
            xc.run()
        if "NO_TARGET" in _state_text(xc.get_state()):
            break
    if not mod_found:
        return {"ok": False,
                "error": "crypto module (cryptsp/advapi32) never mapped",
                "evidence": evidence}
    evidence.append({"label": "crypto_module_mapped"})

    bp = xc.set_breakpoint("CryptDecrypt")
    if not bp.get("ok"):
        return {"ok": False,
                "error": f"bp CryptDecrypt failed: {bp.get('error')}",
                "evidence": evidence}

    def _bp_count() -> int:
        return _bp_text(xc).count("[Normal]")
    if _bp_count() == 0:
        return {"ok": False, "error": "CryptDecrypt bp did not register",
                "evidence": evidence}
    evidence.append({"label": "crypt_bp_set"})

    hits: list[dict] = []
    for n in range(1, max_hits + 1):
        xc.run()
        deadline = time.time() + max_wait_s
        rip = None
        exited = False
        while time.time() < deadline:
            time.sleep(2)
            raw = _state_text(xc.get_state())
            if "NO_TARGET" in raw or "isDebugging: false" in raw:
                exited = True
                break
            st = _parse_state(xc.get_state())
            if st.get("isRunning") == "false":
                rip = _rip(xc)
                break
        if exited:
            evidence.append({"label": f"crypt_hit{n}_exited"})
            break
        if rip is None:
            evidence.append({"label": f"crypt_hit{n}_timeout"})
            break
        regs = _regs(xc)
        hkey = _parse_reg(regs, "rcx")
        final = _parse_reg(regs, "r8")
        flags = _parse_reg(regs, "r9")
        rsp = _parse_reg(regs, "rsp")
        pb_data = _read_u64(xc, rsp + 0x28) if rsp else None
        len_ptr = _read_u64(xc, rsp + 0x30) if rsp else None
        data_len = _read_u32(xc, len_ptr) if len_ptr else None
        hit = {"hit": n, "rip": hex(rip), "hKey": hex(hkey) if hkey else None,
               "final": final, "flags": flags,
               "pbData": hex(pb_data) if pb_data else None,
               "data_len": data_len}
        if pb_data and data_len and 0 < data_len <= 1_048_576:
            cipher = _read_buf(xc, pb_data, data_len)
            hit["cipher_len"] = len(cipher)
            hit["cipher_preview"] = cipher[:64].hex(" ")
        else:
            hit["note"] = "pbData/len not decodable at entry"
        # step out of CryptDecrypt back to caller, re-read as plaintext
        xc.step_out()
        _t.sleep(1)
        # wait for the step-out to land back in caller code
        so_deadline = time.time() + 20
        while time.time() < so_deadline:
            _t.sleep(1)
            st2 = _parse_state(xc.get_state())
            if st2.get("isRunning") == "false":
                break
        if pb_data and data_len and 0 < data_len <= 1_048_576:
            # length may have been updated in place — re-read it
            new_len = _read_u32(xc, len_ptr) if len_ptr else data_len
            plain = _read_buf(xc, pb_data, new_len or data_len)
            hit["plain_len"] = len(plain)
            hit["plain_preview"] = plain[:64].hex(" ")
            ascii_part = plain[:data_len]
            try:
                txt = ascii_part.decode("ascii")
                if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in txt):
                    hit["plain_ascii"] = txt[:200]
            except Exception:
                pass
            if dump_dir and plain:
                try:
                    from pathlib import Path as _P
                    dp = _P(dump_dir)
                    dp.mkdir(parents=True, exist_ok=True)
                    fp = dp / f"crypt-hit{n}-{len(plain)}b.bin"
                    fp.write_bytes(plain)
                    hit["dumped"] = str(fp)
                except Exception as e:
                    hit["dump_error"] = str(e)[:100]
        hits.append(hit)
        evidence.append({"label": f"crypt_hit{n}", **hit})
        st = _parse_state(xc.get_state())
        if "NO_TARGET" in _state_text(xc.get_state()):
            break
    return {"ok": True, "hits": hits, "api": "CryptDecrypt",
            "evidence": evidence}


def wpm_dump(sample: str, xc: X64DbgClient | None = None,
             max_hits: int = 3, max_wait_s: int = 60,
             dump_dir: str | None = None) -> dict:
    """BP WriteProcessMemory -> on each hit decode x64 args
    (rcx=hProcess, rdx=dst, r8=src, r9=size), ReadMemory the SRC buffer and
    dump it. Bounded hits; evidence per hit with hex preview.

    This is the injection/unpack primitive: what malware writes elsewhere.
    """
    xc = xc or X64DbgClient()
    evidence: list[dict] = []
    # NOTE: do NOT rely on auto-EP-break here — .NET/managed binaries run
    # straight through `run` without pausing. Set the API BP immediately
    # after load; its hit is the first (and only needed) pause.
    try:
        xc.call("DeleteAllBreakpoints")
    except Exception:
        pass
    r = xc.load_binary(sample)
    if not r.get("ok"):
        return {"ok": False, "error": f"load failed: {r.get('error')}",
                "evidence": evidence}
    import time as _t
    _t.sleep(2)
    evidence.append({"label": "loaded", "sample": sample})

    bp = xc.set_breakpoint("WriteProcessMemory")
    if not bp.get("ok"):
        return {"ok": False,
                "error": f"bp WriteProcessMemory failed: {bp.get('error')}",
                "evidence": evidence}
    # verify registration: the plugin lists resolved addresses
    # ("... kernel32.dll!"), not the symbol name — so count entries.
    def _bp_count() -> int:
        return _bp_text(xc).count("[Normal]")
    if _bp_count() == 0:
        return {"ok": False, "error": "WPM bp did not register",
                "evidence": evidence}
    evidence.append({"label": "wpm_bp_set"})

    hits: list[dict] = []
    for n in range(1, max_hits + 1):
        xc.run()
        deadline = time.time() + max_wait_s
        rip = None
        while time.time() < deadline:
            time.sleep(2)
            st = _parse_state(xc.get_state())
            if st.get("isRunning") == "false":
                rip = _rip(xc)
                break
        if rip is None:
            evidence.append({"label": f"wpm_hit{n}_timeout"})
            break
        regs = _regs(xc)
        hproc = _parse_reg(regs, "rcx")
        dst = _parse_reg(regs, "rdx")
        src = _parse_reg(regs, "r8")
        size = _parse_reg(regs, "r9")
        hit = {"hit": n, "rip": hex(rip), "hProcess": hex(hproc) if hproc else None,
               "dst": hex(dst) if dst else None,
               "src": hex(src) if src else None, "size": size}
        if src and size and 0 < size <= 1_048_576:
            buf = _read_buf(xc, src, size)
            hit["buf_len"] = len(buf)
            hit["buf_preview"] = buf[:64].hex(" ")
            try:
                txt = buf.decode("ascii")
                if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in txt[:64]):
                    hit["buf_ascii"] = txt[:200]
            except Exception:
                pass
            if dump_dir and buf:
                try:
                    from pathlib import Path as _P
                    dp = _P(dump_dir)
                    dp.mkdir(parents=True, exist_ok=True)
                    fp = dp / f"wpm-hit{n}-{size}b.bin"
                    fp.write_bytes(buf)
                    hit["dumped"] = str(fp)
                except Exception as e:
                    hit["dump_error"] = str(e)[:100]
        else:
            hit["note"] = "src/size not decodable — regs snapshot kept"
            hit["regs"] = regs[:600]
        hits.append(hit)
        evidence.append({"label": f"wpm_hit{n}", **hit})
        # check target still alive before continuing
        st = _parse_state(xc.get_state())
        if "NO_TARGET" in _state_text(xc.get_state()):
            break
    return {"ok": True, "hits": hits, "api": "WriteProcessMemory",
            "evidence": evidence}


# ---------------------------------------------------------------------------
# Scenario 4 — API BP loop (args capture)
# ---------------------------------------------------------------------------
def api_loop(sample: str, api: str, xc: X64DbgClient | None = None,
             max_hits: int = 5, max_wait_s: int = 60) -> dict:
    """BP on an API (e.g. WriteProcessMemory) -> run -> capture regs/stack on
    each hit (bounded max_hits). Each hit's evidence includes the arg regs."""
    xc = xc or X64DbgClient()
    evidence: list[dict] = []
    r = ep_break(sample, xc)
    if not r.get("ok"):
        return r
    evidence.extend(r["evidence"])
    bp = xc.set_breakpoint(api)
    if not bp.get("ok"):
        return {"ok": False, "error": f"bp {api} failed: {bp.get('error')}",
                "evidence": evidence}
    hits = 0
    for _ in range(max_hits):
        xc.run()
        deadline = time.time() + max_wait_s
        while time.time() < deadline:
            time.sleep(2)
            st = _parse_state(xc.get_state())
            if st.get("isRunning") == "false":
                break
        rip = _rip(xc)
        hits += 1
        evidence.append(_pause_evidence(xc, f"{api}_hit{hits}", rip))
    return {"ok": True, "hits": hits, "api": api, "evidence": evidence}


# ---------------------------------------------------------------------------
# Scenario 5 — agentic unpack (deterministic composer)
# ---------------------------------------------------------------------------
def agentic_unpack(sample: str, xc: X64DbgClient | None = None,
                   dump_suffix: str = "_unpacked.exe") -> dict:
    """OEP -> DumpModule -> static re-analysis of the dump -> compare.

    Deterministic fixed sequence (no LLM decisions): find the OEP with
    oep_by_section, dump the module from the live session, re-analyze the
    dumped image with Malcat, and compare original-vs-unpacked verdicts.
    The LangGraph agent drives strategy around this (when to unpack, what
    the comparison means); this function is the reliable tactic.
    """
    import os
    xc = xc or X64DbgClient()
    evidence: list[dict] = []

    # 1. OEP
    oep_res = oep_by_section(sample, xc)
    evidence.extend(oep_res.get("evidence") or [])
    if not oep_res.get("ok"):
        return {"ok": False, "error": f"OEP failed: {oep_res.get('error')}",
                "evidence": evidence}
    oep = oep_res["oep"]
    evidence.append({"label": "oep_found", "oep": hex(oep)})

    # 2. DumpModule from the live session (VM-side path)
    stem = os.path.splitext(os.path.basename(sample))[0]
    vm_dir = os.path.dirname(sample).replace("/", "\\") or r"C:\samples"
    dump_path = f"{vm_dir}\\{stem}{dump_suffix}"
    # module name as x64dbg knows it (stem usually matches ListModules entry)
    try:
        from winre.remote_driver import flare_cfg
        host = flare_cfg()["host"]
    except Exception:
        host = None
    _ = host  # xc already bound; kept for symmetry with other scenarios
    dr = xc.dump_module(stem, dump_path)
    if not dr.get("ok"):
        # retry once: session may need a beat after the OEP pause
        time.sleep(2)
        dr = xc.dump_module(stem, dump_path)
    if not dr.get("ok"):
        return {"ok": False,
                "error": f"DumpModule failed: {dr.get('error')}",
                "evidence": evidence}
    evidence.append({"label": "dumped", "dump_path": dump_path,
                     "dump": dr.get("result")})

    # 3+4. static re-analysis of BOTH images + compare (Malcat MCP).
    # Malcat MCP binds on the VM — address it explicitly, never the
    # localhost default (this code runs on the control-plane host).
    try:
        from winre.mcp import MalcatClient
        try:
            from winre.remote_driver import flare_cfg
            mhost = flare_cfg()["host"]
        except Exception:
            mhost = "192.168.77.42"
        mc = MalcatClient(base=f"http://{mhost}:9009/mcp")
        orig = mc.analyse_file(sample).get("result") or {}
        new = mc.analyse_file(dump_path).get("result") or {}
    except Exception as e:
        return {"ok": False, "error": f"malcat re-analysis failed: {e}",
                "oep": hex(oep), "dump_path": dump_path,
                "evidence": evidence}

    def _verdict(a: dict) -> str:
        v = a.get("verdict") or a.get("summary") or {}
        if isinstance(v, dict):
            return str(v.get("verdict") or v.get("label") or "unknown")
        return str(v or "unknown")

    comparison = {
        "original_verdict": _verdict(orig),
        "unpacked_verdict": _verdict(new),
        "verdicts_match": _verdict(orig) == _verdict(new),
        "original_anomalies": len(orig.get("anomalies") or []),
        "unpacked_anomalies": len(new.get("anomalies") or []),
    }
    evidence.append({"label": "compare", **comparison})
    return {"ok": True, "oep": hex(oep), "dump_path": dump_path,
            "comparison": comparison, "evidence": evidence}


if __name__ == "__main__":
    import argparse
    from winre.mcp.x64dbg_manager import ensure_mcp
    from winre.remote_driver import flare_cfg

    ap = argparse.ArgumentParser(description="x64dbg debug-loop scenarios")
    ap.add_argument("scenario", choices=["ep_break", "oep_by_section", "oep_by_esp",
                                         "wpm_dump", "crypt_dump",
                                         "agentic_unpack", "api_loop"])
    ap.add_argument("sample", help="VM path e.g. C:\\samples\\foo.exe")
    ap.add_argument("--api", default="WriteProcessMemory")
    ap.add_argument("--dump-dir", default=None, help="where to write dumped buffers (host path)")
    args = ap.parse_args()

    ok, info = ensure_mcp()
    if not ok:
        print("x64dbg MCP not available:", info)
        raise SystemExit(1)
    host = flare_cfg()["host"]
    xc = X64DbgClient(base=f"http://{host}:9094")
    fn = {"ep_break": ep_break, "oep_by_section": oep_by_section,
          "oep_by_esp": oep_by_esp,
          "wpm_dump": wpm_dump, "crypt_dump": crypt_dump,
          "agentic_unpack": agentic_unpack,
          "api_loop": api_loop}[args.scenario]
    if args.scenario == "api_loop":
        res = fn(args.sample, args.api, xc)
    elif args.scenario in ("wpm_dump", "crypt_dump"):
        res = fn(args.sample, xc, dump_dir=args.dump_dir)
    else:
        res = fn(args.sample, xc)
    import json as _json
    print(_json.dumps({k: v for k, v in res.items() if k != "evidence"},
                      indent=2, default=str))
    print(f"evidence pauses: {len(res.get('evidence') or [])}")
