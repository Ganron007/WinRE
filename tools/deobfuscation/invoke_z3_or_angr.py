"""invoke_z3_or_angr.py ΓÇö v3 backlog 13.1: auto-invoke wrapper for deobfuscation verification.

Spec: Tools/v3-deploy/v3-plan.md section 6 + 13.1
Toolchain flow:
    quick_scan_v2.py -> LLM + v1 (synthesize_verdict_v1)
                            -> flags: cff_dispatcher_count, mba_claim_detected, path_constraint_needed
                            -> invoke_z3_or_angr(claim_type, sample_path, timeout)
                                -> routes to Z3 / angr / cff_deflatten
                                -> returns structured dict (never raises)
                            -> verdict["z3_results"] / verdict["angr_results"] / verdict["cff_results"]

Constraint: when `enable_deobfuscation_pass = False` (v2 default), this wrapper is a no-op.
v3 enables via `enable_deobfuscation_pass = True` in v2_validate.py.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# v2 baseline: this wrapper is a no-op unless explicitly enabled.
ENABLE_DEOBFUSCATION_PASS_DEFAULT = False
DEFAULT_TIMEOUT_S = 60

# Path to angr pipx venv Python (Remnux-specific; falls back to system python).
ANGR_PYTHON = os.environ.get("ANGR_PYTHON", "/home/remnux/.local/share/pipx/venvs/angr/bin/python")

# Path to cff_deflatten.py GhidraScript (clean RevAI home only).
CFF_DEFLATTEN_PY = os.environ.get(
    "CFF_DEFLATTEN_PY",
    "/opt/revai/cff-deflatten/cff_deflatten.py",
)
# Ghidra analyzeHeadless binary (required for cff_deflatten to run).
GHIDRA_ANALYZE_HEADLESS = os.environ.get("GHIDRA_ANALYZE_HEADLESS", "/opt/ghidra/support/analyzeHeadless")


@dataclass
class DeobfuscationResult:
    tool: str = "none"              # "z3" | "angr" | "cff_deflatten" | "none"
    claim_type: str = ""            # input claim_type
    result: str = "untested"        # "sat" | "unsat" | "verified" | "recovered" | "untested" | "error" | "timeout"
    duration_s: float = 0.0
    evidence: str = ""              # human-readable summary
    raw: dict = field(default_factory=dict)

    def asdict(self) -> dict:
        return asdict(self)


def invoke_z3_or_angr(
    claim_type: str,
    sample_path: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_S,
    claim_text: Optional[str] = None,
    find_addr: Optional[int] = None,
    avoid_addrs: Optional[list] = None,
) -> dict:
    """Top-level entry. Returns a structured dict (never raises).

    claim_type: "mba_identity" | "path_constraint" | "cff_dispatcher" | "opaque_predicate" | "control_flow_obfuscation"
    sample_path: path to the sample binary
    claim_text: for "mba_identity" - the textual claim, e.g. "(x^y) + 2*(x&y) == x+y"
    find_addr: for "path_constraint" - target address to reach
    avoid_addrs: for "path_constraint" - addresses to avoid

    Returns dict with keys: tool, result, duration_s, evidence, raw.
    On timeout/error/no-op: {"tool": None, "result": "untested", "duration_s": 0, "evidence": str(exc)}.
    """
    if not ENABLE_DEOBFUSCATION_PASS_DEFAULT:
        return {
            "tool": None,
            "result": "untested",
            "duration_s": 0.0,
            "evidence": "v2 default: deobfuscation pass disabled",
            "raw": {},
        }
    try:
        t0 = time.time()
        if claim_type == "mba_identity":
            r = invoke_z3(claim_text or "True == True", timeout=timeout)
        elif claim_type == "path_constraint":
            r = invoke_angr(sample_path, find_addr, avoid_addrs or [], timeout=timeout)
        elif claim_type in ("cff_dispatcher", "control_flow_obfuscation"):
            r = invoke_cff_deflatten(sample_path, timeout=timeout)
        elif claim_type == "opaque_predicate":
            r = invoke_z3(claim_text or "True == True", timeout=timeout)
        else:
            r = DeobfuscationResult(
                tool="none",
                claim_type=claim_type,
                result="untested",
                evidence=f"unknown claim_type: {claim_type}",
            )
        r.duration_s = time.time() - t0
        return r.asdict()
    except Exception as e:
        return {
            "tool": None,
            "result": "untested",
            "duration_s": 0.0,
            "evidence": f"{type(e).__name__}: {e}",
            "raw": {"traceback": traceback.format_exc(limit=3)},
        }


def invoke_z3(claim: str, *, timeout: int = DEFAULT_TIMEOUT_S) -> DeobfuscationResult:
    """Verify a single Z3 claim (e.g. '(x^y) + 2*(x&y) == x+y' unsat).

    Uses the z3 Python API directly with BitVecs - more reliable than SMT2 strings.
    The claim string is a Python expression that can reference named BitVecs:
        x, y, z, w  (BitVec(32))
    The claim can be either:
        - "expr1 == expr2" (test for equality, expect unsat on Not(eq))
        - "expr" (test for tautology, expect unsat on Not(expr))
    Returns DeobfuscationResult.
    """
    r = DeobfuscationResult(tool="z3", claim_type="mba_identity", result="error")
    try:
        import z3
        x, y, z, w = z3.BitVecs("x y z w", 32)
        # Namespace for eval: BitVecs + z3 (so user can use z3.BV* if needed)
        ns = {"x": x, "y": y, "z": z, "w": w, "z3": z3}
        s = z3.Solver()
        s.set("timeout", int(timeout * 1000))  # ms
        if " == " in claim:
            lhs_str, rhs_str = claim.split(" == ", 1)
            lhs_e = eval(lhs_str, {"__builtins__": {}}, ns)
            rhs_e = eval(rhs_str, {"__builtins__": {}}, ns)
            s.add(z3.Not(lhs_e == rhs_e))
            test_kind = "equality"
        else:
            claim_e = eval(claim, {"__builtins__": {}}, ns)
            s.add(z3.Not(claim_e))
            test_kind = "tautology"
        check = s.check()
        if str(check) == "unsat":
            r.result = "unsat"
            r.evidence = f"Z3 verified: {test_kind} holds (unsat). timeout={timeout}s"
        elif str(check) == "sat":
            r.result = "sat"
            r.evidence = "Z3 disproved: counterexample found"
            try:
                r.raw["model"] = str(s.model())[:500]
            except Exception:
                pass
        else:
            r.result = "timeout"
            r.evidence = f"Z3 returned {check} (likely timeout after {timeout}s)"
    except Exception as e:
        r.result = "error"
        r.evidence = f"Z3 error: {type(e).__name__}: {e}"
    return r


def invoke_angr(
    sample_path: str,
    find_addr: Optional[int] = None,
    avoid_addrs: Optional[list] = None,
    *,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> DeobfuscationResult:
    """angr symbolic exec to find a path constraint.

    Uses the angr pipx venv (Remnux-specific) via subprocess.
    Inline angr script is generated on the fly.
    Returns DeobfuscationResult.
    """
    r = DeobfuscationResult(tool="angr", claim_type="path_constraint", result="error")
    if find_addr is None:
        r.result = "untested"
        r.evidence = "angr invoke requires find_addr (target address to reach)"
        return r
    if not Path(sample_path).is_file():
        r.result = "untested"
        r.evidence = f"sample not found: {sample_path}"
        return r
    if not Path(ANGR_PYTHON).is_file():
        r.result = "untested"
        r.evidence = f"angr Python not found at {ANGR_PYTHON}; install with: pipx install angr"
        return r
    avoid_args = ",".join(str(a) for a in (avoid_addrs or []))
    find_arg = f"0x{int(find_addr):x}" if isinstance(find_addr, int) else str(find_addr)
    inline = f'''
import sys, json
import angr
p = angr.Project("{sample_path}", auto_load_libs=False)
find = {find_arg}
avoid = [{avoid_args}]
sm = p.factory.simulation_manager()
sm.explore(find=find, avoid=avoid, n={timeout})
if sm.found:
    print(json.dumps({{"result": "recovered", "path_len": len(sm.found[0].history.bbl_addrs)}}))
else:
    print(json.dumps({{"result": "no_path", "active": len(sm.active)}}))
'''
    try:
        proc = subprocess.run(
            [ANGR_PYTHON, "-c", inline],
            capture_output=True, text=True, timeout=timeout + 30,
        )
        last_line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        try:
            j = json.loads(last_line)
            r.result = j.get("result", "error")
            r.raw = j
            r.evidence = f"angr explore: {j}"
        except json.JSONDecodeError:
            r.result = "error"
            r.evidence = f"angr output unparseable: {last_line[:200] or proc.stderr[:200]}"
    except subprocess.TimeoutExpired:
        r.result = "timeout"
        r.evidence = f"angr timed out after {timeout}s"
    except Exception as e:
        r.result = "error"
        r.evidence = f"angr error: {type(e).__name__}: {e}"
    return r


def invoke_cff_deflatten(sample_path: str, *, timeout: int = DEFAULT_TIMEOUT_S) -> DeobfuscationResult:
    """Invoke the GhidraScript CFF deflatten on sample_path. Returns recovered CFG edges.

    Requires cff_deflatten.py (the PyGhidra script from v3-deploy/cff-deflatten/).
    The script does not require the full Ghidra headless pipeline (pyghidra loads
    the binary directly).

    If sample_path ends in .i64, extract the original binary path from
    the corresponding session.json and use that instead (pyghidra cannot
    load pre-built .i64 databases; it needs raw PE/ELF/etc.).
    """
    r = DeobfuscationResult(tool="cff_deflatten", claim_type="cff_dispatcher", result="error")
    if not Path(sample_path).is_file():
        r.result = "untested"
        r.evidence = f"sample not found: {sample_path}"
        return r
    if not Path(CFF_DEFLATTEN_PY).is_file():
        r.result = "untested"
        r.evidence = f"cff_deflatten.py not found at {CFF_DEFLATTEN_PY}; copy from v3-deploy/cff-deflatten/"
        return r
    # If sample_path is an .i64, resolve to the raw binary via session.json
    if sample_path.endswith(".i64"):
        raw_path = _resolve_raw_from_i64(sample_path)
        if raw_path:
            sample_path = raw_path
            r.evidence = f"resolved .i64 -> {raw_path}; "
    try:
        proc = subprocess.run(
            [sys.executable, CFF_DEFLATTEN_PY, "--input", sample_path, "--json"],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
            try:
                j = json.loads(proc.stdout)
                r.result = "recovered" if j.get("candidates") else "no_candidates"
                r.raw = j
                r.evidence += f"cff_deflatten: {len(j.get('candidates', []))} CFF candidates found"
            except json.JSONDecodeError:
                r.result = "error"
                r.evidence += f"cff_deflatten output not JSON: {proc.stdout[:200]}"
        else:
            r.result = "error"
            r.evidence += f"cff_deflatten failed (exit {proc.returncode}): {proc.stderr[:200] or proc.stdout[:200]}"
    except subprocess.TimeoutExpired:
        r.result = "timeout"
        r.evidence += f"cff_deflatten timed out after {timeout}s"
    except Exception as e:
        r.result = "error"
        r.evidence += f"cff_deflatten error: {type(e).__name__}: {e}"
    return r


def _resolve_raw_from_i64(i64_path: str) -> str | None:
    """Given a .i64 file path, return the raw binary path via session.json.

    The .i64 file lives in /opt/samples/corpus/<project>/<sha>/<name>.i64
    and the raw binary is the same directory with the .exe/.dll extension.
    We find it by looking in the parent directory for the sample_path
    recorded in session.json, or by stripping the .i64 suffix.
    """
    import json
    p = Path(i64_path)
    parent = p.parent
    # 1. Try session.json in the same dir
    sess_path = parent / "session.json"
    if sess_path.exists():
        try:
            sess = json.loads(sess_path.read_text())
            raw = sess.get("sample_path")
            if raw and Path(raw).exists():
                return raw
        except Exception:
            pass
    # 2. Try parent-of-parent (samples live in <project>/<sha>/)
    grandparent = parent.parent
    if grandparent.exists():
        sess_path = grandparent / "session.json"
        if sess_path.exists():
            try:
                sess = json.loads(sess_path.read_text())
                raw = sess.get("sample_path")
                if raw and Path(raw).exists():
                    return raw
            except Exception:
                pass
    # 3. Try to find a non-.i64/.id*/.nam/.til file in the same dir
    for f in parent.iterdir():
        if f.is_file() and f.suffix.lower() not in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
            return str(f)
    return None


def _self_test() -> None:
    """Smoke test: verify invoke_z3 works on known MBA identities."""
    import z3
    print("=== invoke_z3_or_angr self-test ===")
    # Test 1: classic MBA identity (x^y) + 2*(x&y) == x+y
    r1 = invoke_z3("(x ^ y) + 2 * (x & y) == x + y", timeout=10)
    print(f"  Test 1 (x^y + 2*(x&y) == x+y): tool={r1.tool} result={r1.result} duration={r1.duration_s:.2f}s")
    print(f"    evidence: {r1.evidence}")
    assert r1.result == "unsat", f"expected unsat (tautology), got {r1.result}"

    # Test 2: opaque predicate (x*x - x) is always even
    r2 = invoke_z3("((x * x - x) & 1) == 0", timeout=10)
    print(f"  Test 2 (x*x - x always even): tool={r2.tool} result={r2.result}")
    assert r2.result == "unsat", f"expected unsat, got {r2.result}"

    # Test 3: disproving claim (x == y is not a tautology)
    r3 = invoke_z3("x == y", timeout=10)
    print(f"  Test 3 (x == y is not tautology): tool={r3.tool} result={r3.result}")
    assert r3.result == "sat", f"expected sat (not tautology), got {r3.result}"

    # Test 4: NO-OP default (enable_deobfuscation_pass = False)
    r4 = invoke_z3_or_angr("mba_identity", "/nonexistent", claim_text="x == x")
    print(f"  Test 4 (no-op default): tool={r4['tool']} result={r4['result']}")
    assert r4["result"] == "untested", f"expected untested (no-op), got {r4['result']}"

    print("  ALL TESTS PASSED")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        _self_test()
    else:
        print("invoke_z3_or_angr.py ΓÇö v3 backlog 13.1 wrapper (importable module)")
        print("Usage: from invoke_z3_or_angr import invoke_z3_or_angr, invoke_z3, invoke_angr, invoke_cff_deflatten")
        print("Self-test: python3 invoke_z3_or_angr.py --test")
