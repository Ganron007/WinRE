#!/usr/bin/env python3
"""evidence.py — stage-tagged evidence pack for the WinRE pipeline.

Mirrors RevAI's evidence-pack discipline: every stage writes a tagged folder
under logs/<sha>/, the LLM can only cite what a deterministic tool emitted,
and a report carries a `source` (llm_judge vs deterministic_fallback) so a
stubbed run can never look green.

Layout (RevAI-style mode sections — one self-contained case per engine):
    logs/<sha>/
      static/                 deterministic engine section (RevAI scripted)
        intake/               metadata, magic, format tools
        quick/                deterministic triage (Malcat/SQL) + verdict
        dynamic/              detonation pack (META.json, frida, procmon, ...)
        deep/                 deterministic checklist pass
        yara/                 generated YARA/Sigma + rule reports
        report/               final report (source-tagged) + analyst-next
        audit.json            truly_green gate
        META.json             pack-level mode/engine/source
        stage_trace.json      stage ordering/timing trace
      agentic/                LangGraph engine section (RevAI agentic)
        <same stage layout>
      snapshot.json           HITL snapshot ledger (VM-state, mode-independent)

Same-sample/same-mode reruns overwrite their section; the other section is
untouched. Pre-sectioning packs (flat stages directly under logs/<sha>/)
are read as legacy rows.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidencePack:
    """Read/write a stage-tagged evidence pack under logs/<sha>/<mode>/."""

    STAGES = ("intake", "quick", "dynamic", "deep", "yara", "report")

    # Deep-dive engine sections. mode=None = legacy flat layout logs/<sha>/
    # (read-only compat for old packs).
    #
    # FOUR independent producers, not two. `--agentic-dbg` and `--dynamic` are
    # CAPABILITIES, not modes, but they produce genuinely different evidence
    # from a plain agentic run - an unpacked image and a full detonation. When
    # they shared a pack root, runs overwrote each other (see docs/internal/
    # DESIGN.md 1.2e): run 3 clobbered run 2's deep.json, so no two modes could
    # ever be compared and the only "verdict change" observable was
    # last-write-wins. Each capability now owns its own root.
    MODES = ("static", "agentic", "dbg", "dynamic")
    # capability flags that select a pack root; everything else is `static` or
    # `agentic` on its given engine
    MODE_AGENTIC_DBG = "dbg"
    MODE_DYNAMIC = "dynamic"

    @classmethod
    def resolve_mode(cls, mode: str | None, *, agentic_dbg: bool = False,
                     dynamic: bool = False) -> str:
        """The pack mode from the CLI's mode + capability flags.

        A single authority, used by the driver and the pipeline alike, so the
        two can never disagree about where a run's evidence lands.
        """
        if mode == "static":
            # static has no debug/detonation variants
            return "static"
        if dynamic:
            return cls.MODE_DYNAMIC
        if agentic_dbg:
            return cls.MODE_AGENTIC_DBG
        return "agentic"

    def __init__(self, logs_dir: Path, sha: str, mode: str | None = None):
        self.logs_dir = Path(logs_dir)
        self.sha = sha
        if mode is not None and mode not in self.MODES:
            # fail closed. An unknown mode used to collapse to the legacy flat
            # layout and quietly merge two runs' evidence into one pack.
            raise ValueError(
                f"unknown pack mode {mode!r}; expected one of {self.MODES}")
        self.mode: str | None = mode if mode in self.MODES else None
        self.root = (self.logs_dir / sha / self.mode) if self.mode \
            else (self.logs_dir / sha)
        self.stages = {s: self.root / s for s in self.STAGES}

    def ensure(self) -> "EvidencePack":
        self.root.mkdir(parents=True, exist_ok=True)
        for p in self.stages.values():
            p.mkdir(parents=True, exist_ok=True)
        return self

    def write(self, stage: str, name: str, payload: dict) -> Path:
        """Write a JSON artifact into a stage folder. Returns the path."""
        p = self.stages[stage] / name
        p.write_text(json.dumps(payload, indent=2, default=str) + "\n",
                     encoding="utf-8")
        return p

    def read(self, stage: str, name: str) -> dict | None:
        p = self.stages[stage] / name
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def stage_artifacts(self, stage: str) -> list[str]:
        d = self.stages[stage]
        if not d.is_dir():
            return []
        return sorted(f.name for f in d.iterdir() if f.is_file())

    def manifest(self) -> dict:
        return {
            "sha256": self.sha,
            "mode": self.mode,
            "stages": {s: self.stage_artifacts(s) for s in self.STAGES},
            "generated_at": utcnow(),
        }


def pack_sections(sha_dir: Path) -> list[dict]:
    """Mode sections present under logs/<sha>/ (for UI rows).

    Returns [{mode, root}] in MODES order, plus a legacy entry
    ({mode: None}) when flat stages exist directly under the sha dir.
    """
    out: list[dict] = []
    if not sha_dir.is_dir():
        return out
    for m in EvidencePack.MODES:
        if (sha_dir / m).is_dir():
            out.append({"mode": m, "root": sha_dir / m})
    if any((sha_dir / s).is_dir() for s in EvidencePack.STAGES):
        out.append({"mode": None, "root": sha_dir})
    return out


def verdict_fields(verdict) -> tuple[dict | None, str | None, bool]:
    """Normalize a deep-dive verdict into (object, label, missing).

    Both engines hand back a dict (agentic: normalized LLM object; static:
    rules object); older/partial paths hand back a bare label string or
    nothing at all. `missing=True` means "this stage produced no verdict",
    which the audit must never let pass as green (RevAI handoff item 2).
    """
    if isinstance(verdict, dict):
        label = str(verdict.get("verdict") or "").strip() or None
        return (verdict if label else None), label, not bool(label)
    if isinstance(verdict, str) and verdict.strip():
        label = verdict.strip()
        return {"verdict": label}, label, False
    return None, None, True


MODES = EvidencePack.MODES


def resolve_pack_mode(mode: str | None, *, agentic_dbg: bool = False,
                      dynamic: bool = False) -> str:
    """The pack mode for a run. One authority, used by every entry point.

    Four independent producers (docs/internal/DESIGN.md section 3): `static`,
    `agentic`, `dbg`, `dynamic`. A sample analysed with two modes yields two
    packs and reporting compares them, instead of the second overwriting the
    first - which is what happened when dbg/dynamic shared the agentic root
    (DESIGN.md section 1.2e).
    """
    return EvidencePack.resolve_mode(mode, agentic_dbg=agentic_dbg,
                                     dynamic=dynamic)


def sha_of(pack_root) -> str:
    """The sample sha for a pack root, derived SAFELY.

    A pack root is `<logs>/<sha>` or `<logs>/<sha>/<mode>`, so `pack_root.name`
    is the MODE ("static"/"agentic") in the second case - not the hash. Code
    that assumed otherwise wrote "static" into `intake.json -> sha256` and into
    every report header (code audit 2026-10-06), which silently poisons any
    third-party ingestion keyed on SHA256.

    Prefer `EvidencePack.sha` when you hold the pack; use this when all you have
    is a path.
    """
    root = Path(pack_root)
    if root.name in MODES and root.parent != root:
        return root.parent.name
    return root.name


def pack_verdict(section_root: Path) -> dict:
    """Read a section's verdict from deep.json (top level, then agent block).

    Returns {"verdict", "verdict_obj", "source", "present"}. `present=False`
    means the deep stage produced no verdict — an unmet expectation, not a
    pass.
    """
    try:
        d = json.loads((Path(section_root) / "deep" / "deep.json")
                       .read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"verdict": None, "verdict_obj": None, "source": None,
                "llm_roles": None, "present": False}
    agent = d.get("agent") or {}
    raw = d.get("verdict_obj") if d.get("verdict") else agent.get("verdict")
    obj, label, missing = verdict_fields(raw)
    return {"verdict": label, "verdict_obj": obj,
            "source": d.get("source") or agent.get("source"),
            "llm_roles": d.get("llm_roles") or agent.get("llm_roles"),
            "present": not missing}


#: files that are NOT detonation evidence (our own stage/skip wrappers)
_DYNAMIC_WRAPPERS = ("STAGE.json", "SKIP.json")


def dynamic_skip_record(*, reason: str, ok: bool, error: str | None = None,
                        summary: str = "", preserved_previous: str | None = None,
                        preserved_artifacts: int | None = None,
                        extra: dict | None = None) -> dict:
    """The payload of a sibling `dynamic/SKIP.json`, in ONE place.

    A consumer that only wants to know "did this section detonate, and is the
    previous pack safe?" reads that single file instead of interpreting the
    stage wrapper (RevAI handoff 2026-09-27 item 3 asked for a sibling skip
    file; the audit/UI read STAGE.json, so both are written from here and
    cannot drift).

    `reason` is the machine-readable cause: "not_requested" (this run never
    asked) or "snapshot_gate_blocked" (it asked and the gate refused).
    """
    out = {
        "schema": "winre-dynamic-skip/v1",
        "stage": "dynamic",
        "ran": False,
        "skipped": True,
        "ok": bool(ok),
        "reason": reason,
        "error": error,
        "summary": summary or reason,
        "cleared_previous": False,
        "preserved_previous": preserved_previous,
        "has_detonation_evidence": False,
        "note": ("This run produced NO detonation evidence in this section. "
                 "An earlier pack, if any, is at `preserved_previous` "
                 "(previous runs are moved, never deleted)."),
        "recorded_at": utcnow(),
    }
    if preserved_artifacts is not None:
        out["preserved_artifacts"] = int(preserved_artifacts)
    if extra:
        out.update(extra)
    return out


def write_dynamic_skip(pack: "EvidencePack", payload: dict) -> Path | None:
    """Write the sibling `dynamic/SKIP.json` (never touches STAGE.json)."""
    try:
        p = pack.stages.get("dynamic")
        if p is None:
            return None
        p.mkdir(parents=True, exist_ok=True)
        path = p / "SKIP.json"
        path.write_text(json.dumps(payload, indent=2, default=str) + "\n",
                        encoding="utf-8")
        return path
    except Exception:  # noqa: BLE001
        return None


def preserve_dynamic(pack: "EvidencePack", *, stamp: str | None = None) -> dict:
    """MOVE an existing dynamic pack aside; never delete it. Append-only.

    Used by every path that leaves `dynamic/` without a detonation of its own
    (static-only run, gate refusal). The old gate-refusal path deleted the
    pack and then wrote a record claiming "moved, never deleted" - a directly
    self-contradicting artifact (code audit 2026-09-28, HIGH).
    """
    out: dict = {"preserved_previous": None, "preserved_artifacts": 0,
                 "cleared_previous": False}
    try:
        import shutil
        d = pack.stages.get("dynamic")
        if not (d and d.exists()):
            return out
        payload = [ch for ch in d.iterdir() if ch.name not in _DYNAMIC_WRAPPERS]
        if not payload:
            return out
        stamp = stamp or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        dest = pack.root / "previous_runs" / f"dynamic_{stamp}"
        n = 1
        while dest.exists():          # never collide: a same-second move would
            n += 1                     # NEST into the existing dir and the
            dest = pack.root / "previous_runs" / f"dynamic_{stamp}-{n}"  # pointer
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(d), str(dest))
        d.mkdir(parents=True, exist_ok=True)
        out["preserved_previous"] = f"previous_runs/{dest.name}"
        out["preserved_artifacts"] = len(payload)
    except Exception as e:            # noqa: BLE001
        out["preserve_error"] = str(e)[:150]
    return out


def mark_dynamic_not_requested(pack: "EvidencePack") -> dict:
    """Fresh dynamic/STAGE.json + SKIP.json for a run that never detonated.

    EVIDENCE IS APPEND-ONLY (RevAI handoff 2026-09-27 item 3): a static-only
    run must never destroy a previous run's dynamic pack in the same mode
    section. When a previous pack exists it is MOVED (never deleted) to
    `previous_runs/dynamic_<ts>/` and both records point at it, so a consumer
    can tell "this run detonated nothing" from "evidence discarded".

    The stage wrapper is still rewritten on every static-only run: a stale
    gate-blocked `ok: false` STAGE.json must not make a static-only run look
    "dynamic blocked" (found 2026-09-20). Never raises.
    """
    out: dict = {"ok": True, "ran": False, "skipped": "not requested",
                 "cleared_previous": False, "preserved_previous": None}
    try:
        import shutil
        d = pack.stages.get("dynamic")
        if d and d.exists():
            # real evidence = anything that is not one of our own wrappers
            payload = [ch for ch in d.iterdir() if ch.name not in _DYNAMIC_WRAPPERS]
            if payload:
                stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
                dest = pack.root / "previous_runs" / f"dynamic_{stamp}"
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.move(str(d), str(dest))
                    d.mkdir(parents=True, exist_ok=True)
                    out["preserved_previous"] = f"previous_runs/{dest.name}"
                    out["preserved_artifacts"] = len(payload)
                except OSError as e:
                    # never destroy: if the move fails, leave the pack alone
                    # and say so (an honest gap beats silent evidence loss)
                    out["preserved_previous"] = None
                    out["preserve_error"] = str(e)[:150]
        out["summary"] = ("dynamic not requested (static-only run)"
                          + (f"; previous pack preserved at "
                             f"{out['preserved_previous']}"
                             if out["preserved_previous"] else ""))
        if not out["preserved_previous"]:
            # Nothing left in dynamic/ to move — but an earlier pack from this
            # section may already sit in previous_runs/ (a previous static-only
            # run moved it there). Point at the newest one, so a consumer that
            # reads ONLY SKIP.json still learns where this section's most recent
            # detonation lives.
            arch = pack.root / "previous_runs"
            if arch.is_dir():
                prior = sorted(arch.glob("dynamic_*"))
                if prior:
                    out["preserved_previous"] = f"previous_runs/{prior[-1].name}"
                    out["preserved_already_archived"] = True
                    out["summary"] += (f"; most recent earlier pack: "
                                       f"{out['preserved_previous']}")
        pack.write("dynamic", "STAGE.json", {
            "stage": "dynamic", "ok": True, "ran": False,
            "skipped": "not requested",
            "summary": out["summary"],
            "cleared_previous": False,
            "preserved_previous": out["preserved_previous"],
        })
        write_dynamic_skip(pack, dynamic_skip_record(
            reason="not_requested", ok=True, summary=out["summary"],
            preserved_previous=out["preserved_previous"],
            preserved_artifacts=out.get("preserved_artifacts"),
            extra=({"preserved_already_archived": True}
                   if out.get("preserved_already_archived") else None)))
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:150]
    return out


def write_execution_plan(pack: "EvidencePack", plan: dict) -> Path:
    """Record the run-level execution plan in the pack (audit reads it)."""
    payload = dict(plan)
    payload["recorded_at"] = utcnow()
    p = pack.root / "execution_plan.json"
    p.write_text(json.dumps(payload, indent=2, default=str) + "\n",
                 encoding="utf-8")
    return p


def stage_result(stage: str, ok: bool, *, error: str | None = None,
                 summary: str | None = None, **extra) -> dict:
    """A stage's META-shaped result with the honest ok/error contract."""
    out = {
        "stage": stage,
        "ok": ok,
        "error": error,
        "summary": summary,
        "started_at": utcnow(),
        "elapsed_s": extra.pop("elapsed_s", None),
    }
    out.update(extra)
    return out


def source_tagged(kind: str, source: str, content: dict) -> dict:
    """Every report/verdict carries a source: llm_judge or deterministic_fallback."""
    out = dict(content)
    out["source"] = source
    return out
