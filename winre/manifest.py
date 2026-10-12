"""winre/manifest.py — the per-run artifact manifest (design §8).

A detonation produces files in several **collection domains**, and until now
nothing recorded which domain a file came from, whether the source that should
have produced it actually did, or what the file's hash was. Two consequences:

  * a reader cannot tell a complete capture from a missing one, so a missing
    capture is indistinguishable from an empty one;
  * after the stale-sibling fix (`evidence.archive_stage_for_fresh_run`) a run's
    directory is clean, but nothing *proves* it is clean.

This module writes `manifest.json` beside the pulled evidence: one record per
file with a stable id, hash, size, source, collection domain, and the producer
that made it — plus a per-source coverage verdict.

The honesty rule, which is the whole point:

    never encode a missing capture as an empty successful capture.

A source that was not asked for is `not_requested`. A source that was asked for
and produced nothing is `partial` or `failed` with a reason. It is never
`complete` with an empty file list.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

SCHEMA = "winre-artifact-manifest/v1"

# Collection domains (design section 1). These describe WHERE a file was
# collected, not how much to trust it — raw evidence is untrusted data in every
# domain.
IN_GUEST = "in_guest"      # collected inside the analysis VM
OFF_BOX = "off_box"        # collected outside the analysis guest
DERIVED = "derived"        # produced by the control plane from the above

# Files that are our own bookkeeping, not evidence from a source.
_WRAPPERS = ("STAGE.json", "SKIP.json", "manifest.json", "META.json",
             "META.job.json", "SCHEMA.md", "findings.json")

# rel-path (posix, lower) -> (source, domain, kind)
# Derived from an inventory of every path that actually appears in the packs on
# disk, not from what we wish were there.
_PATH_MAP: dict[str, tuple[str, str, str]] = {
    # ---- frida: userland API hooks, in-guest, most tamperable surface -------
    "frida_trace.jsonl":            ("frida", IN_GUEST, "raw_observation"),
    "frida_trace.json":             ("frida", IN_GUEST, "raw_observation"),
    "frida_trace.jsonl.run.json":   ("frida", IN_GUEST, "run_metadata"),
    "frida.stderr.txt":             ("frida", IN_GUEST, "collector_log"),
    "frida.stdout.txt":             ("frida", IN_GUEST, "collector_log"),
    "job.log":                      ("frida", IN_GUEST, "collector_log"),
    "frida_summary.json":           ("frida", DERIVED, "derived_summary"),
    # ---- procmon: kernel-driver system events, in-guest ---------------------
    "procmon.csv":                  ("procmon", IN_GUEST, "raw_observation"),
    "procmon.pml":                  ("procmon", IN_GUEST, "raw_observation"),
    "procmon_summary.json":         ("procmon", DERIVED, "derived_summary"),
    "behavior_timeline.csv":        ("procmon", DERIVED, "derived_timeline"),
    # ---- memory: procdump of the live process, in-guest ---------------------
    "post_mortem.json":             ("memory", IN_GUEST, "raw_observation"),
    # ---- network: FakeNet today, in-guest; the design moves it off-box ------
    "network.json":                 ("network", IN_GUEST, "raw_observation"),
    "network_intel.json":           ("network", DERIVED, "derived_summary"),
    "emu_diff.json":                ("network", DERIVED, "derived_comparison"),
    # ---- windbg: mcp-windbg on the VM, in-guest ----------------------------
    "windbg_analysis.json":         ("windbg", IN_GUEST, "derived_analysis"),
    # ---- process snapshots: psutil, in-guest -------------------------------
    "process_snapshot.json":        ("process_snapshot", IN_GUEST, "raw_observation"),
    "process_snapshot_pre.json":    ("process_snapshot", IN_GUEST, "raw_observation"),
    "process_snapshot_post.json":   ("process_snapshot", IN_GUEST, "raw_observation"),
    # ---- malcat: commercial triage, in-guest -------------------------------
    "malcat-triage.json":           ("malcat", IN_GUEST, "raw_observation"),
    # ---- analyst next: a checklist, not a verdict --------------------------
    "analyst_next.json":            ("analyst_next", DERIVED, "derived_checklist"),
    "analyst-next.md":              ("analyst_next", DERIVED, "derived_checklist"),
    # ---- host-side analysis over pulled evidence ---------------------------
    "post_analysis.json":           ("host_analysis", DERIVED, "derived_analysis"),
    # ---- the VM job's own record of what ran -------------------------------
    "meta.job.json":                ("job", IN_GUEST, "run_metadata"),
}

# Directory prefixes, checked before the exact-name map.
_DIR_MAP: dict[str, tuple[str, str, str]] = {
    "memory/":       ("memory", IN_GUEST, "raw_observation"),
    "network_raw/":  ("network", IN_GUEST, "raw_observation"),
    "off_box/":      ("external_capture", OFF_BOX, "raw_observation"),
    "x64dbg/":       ("x64dbg", IN_GUEST, "raw_observation"),
    "runs/":         ("run_archive", IN_GUEST, "archived_evidence"),
}

# What each source is *supposed* to produce when it runs. Used to decide
# `complete` vs `partial` — a source that ran but is missing its primary output
# is partial, not complete-with-nothing.
_EXPECTED: dict[str, tuple[str, ...]] = {
    "frida":            ("frida_trace.jsonl",),
    "procmon":          ("procmon.csv",),
    "memory":           ("memory/",),
    "network":          ("network_raw/",),
    "windbg":           ("windbg_analysis.json",),
    "process_snapshot": ("process_snapshot_pre.json",),
    "malcat":           ("malcat-triage.json",),
}

# Hash budget. A stage is routinely 300-800 MB; hashing all of it is seconds, not
# minutes, but a 5 GB procmon.pml across many packs is not free. Above the cap
# the hash is recorded as absent WITH A REASON — never as a placeholder that
# looks like a hash.
HASH_CAP_BYTES = int(os.environ.get("WINRE_MANIFEST_HASH_CAP",
                                    str(2 * 1024 ** 3)))


def classify(rel: str) -> tuple[str, str, str]:
    """(source, domain, kind) for a stage-relative path.

    Unknown files are recorded as `unclassified` rather than dropped: a file we
    do not recognise is exactly the one a reader needs to see.
    """
    p = rel.replace("\\", "/").lower()
    if p in _PATH_MAP:
        return _PATH_MAP[p]
    for prefix, triple in _DIR_MAP.items():
        if p.startswith(prefix):
            return triple
    for name, triple in _PATH_MAP.items():
        if p.endswith("/" + name):
            return triple
    return ("unclassified", IN_GUEST, "unknown")


def _hash(path: Path) -> tuple[str | None, str | None]:
    """sha256 of a file, or (None, reason) when it was not hashed."""
    try:
        size = path.stat().st_size
    except OSError as e:
        return None, f"stat failed: {e}"
    if size > HASH_CAP_BYTES:
        return None, (f"not hashed: {size} B exceeds the "
                      f"{HASH_CAP_BYTES} B cap (WINRE_MANIFEST_HASH_CAP)")
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError as e:
        return None, f"read failed: {e}"
    return h.hexdigest(), None


def _artifact_id(source: str, rel: str, n: int) -> str:
    """Stable, human-readable, unique within the manifest."""
    stem = rel.replace("\\", "/").split("/")[-1]
    stem = "".join(c if c.isalnum() else "-" for c in stem).strip("-")[:40]
    return f"{source}-{n:03d}-{stem or 'file'}"


def build_manifest(stage_dir: Path, *, run_id: str, sha256: str = "",
                   mode: str = "dynamic", requested: dict | None = None,
                   meta: dict | None = None,
                   hash_files: bool = True) -> dict:
    """Write `manifest.json` into `stage_dir` and return it.

    `requested` names the sources this run asked for, so a source that was never
    requested is `not_requested` rather than silently missing. `meta` is the
    stage's META.json when present — recorded errors are what turn a source into
    `failed` instead of `partial`.
    """
    stage_dir = Path(stage_dir)
    meta = meta or {}
    requested = requested or {}
    artifacts: list[dict] = []
    seen: dict[str, list[str]] = {}

    for path in sorted(p for p in stage_dir.rglob("*") if p.is_file()):
        rel = str(path.relative_to(stage_dir)).replace("\\", "/")
        if rel in _WRAPPERS:
            continue
        source, domain, kind = classify(rel)
        digest, why = (_hash(path) if hash_files else (None, "hashing disabled"))
        n = len(seen.get(source, [])) + 1
        seen.setdefault(source, []).append(rel)
        artifacts.append({
            "id": _artifact_id(source, rel, n),
            "path": rel,
            "sha256": digest,
            "hash_skipped_reason": why,
            "size_bytes": path.stat().st_size,
            "kind": kind,
            "source_domain": domain,
            "source": source,
            "derived_from": [],
        })

    coverage = _coverage(seen, requested, meta)
    return {
        "schema": SCHEMA,
        "run_id": run_id,
        "sample_sha256": sha256,
        "mode": mode,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stage_dir": str(stage_dir),
        "artifact_count": len(artifacts),
        "sources": sorted({a["source"] for a in artifacts}),
        "coverage": coverage,
        "artifacts": artifacts,
        "note": ("Coverage describes COLLECTION, not trust: raw evidence is "
                 "untrusted data in every domain. A source recorded as "
                 "complete produced its primary output; it does not mean the "
                 "sample behaved, or that the sample could not have tampered "
                 "with the collector."),
    }


def _coverage(seen: dict[str, list[str]], requested: dict,
              meta: dict) -> dict[str, dict]:
    """Per-source coverage: complete | partial | failed | not_requested.

    The ordering matters. A source that was not requested is `not_requested`
    even if a stray file from it exists; a source that was requested and is
    missing its primary output is `partial` or `failed`, never `complete`.
    """
    errors = (meta.get("errors") or {}) if isinstance(meta, dict) else {}
    out: dict[str, dict] = {}
    for source, expected in _EXPECTED.items():
        present = seen.get(source, [])
        # "was this asked for" — an explicit request wins; otherwise, files from
        # this source being present is the evidence. `source in present` tests
        # for the literal string in a list of PATHS and is always False, which
        # made a source that plainly ran read as `not_requested`.
        was_requested = bool(requested.get(source, bool(present)))
        if not was_requested:
            out[source] = {"status": "not_requested",
                           "reason": "this run did not ask for it"}
            continue
        if not present:
            err = errors.get(source)
            out[source] = ({
                "status": "failed",
                "reason": f"requested but produced nothing: {err}"
                          if err else "requested but produced nothing",
            } if err else {
                "status": "partial",
                "reason": "requested but produced no files",
            })
            continue
        missing = [e for e in expected
                   if not any(p == e or p.startswith(e) for p in present)]
        if missing:
            out[source] = {
                "status": "partial",
                "reason": f"missing primary output: {', '.join(missing)}",
                "present": present[:10],
            }
            continue
        out[source] = {"status": "complete",
                       "reason": "primary output present",
                       "present": present[:10]}
    return out


def write_manifest(stage_dir: Path, **kw) -> dict:
    """Build and write; never raises (a manifest failure must not fail a run)."""
    try:
        m = build_manifest(Path(stage_dir), **kw)
        (Path(stage_dir) / "manifest.json").write_text(
            json.dumps(m, indent=2, default=str) + "\n", encoding="utf-8")
        return m
    except Exception as e:                                   # pragma: no cover
        return {"schema": SCHEMA, "ok": False,
                "error": f"{type(e).__name__}: {e}"}


def read_manifest(stage_dir: Path) -> dict:
    p = Path(stage_dir) / "manifest.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def incomplete_sources(stage_dir: Path) -> list[tuple[str, str]]:
    """(source, reason) for every source that is not `complete`.

    This is what a report and the findings plane should consult instead of
    inferring "no file means nothing happened".
    """
    m = read_manifest(stage_dir)
    out = []
    for source, rec in (m.get("coverage") or {}).items():
        if rec.get("status") != "complete":
            out.append((source, f"{rec.get('status')}: {rec.get('reason', '')}"))
    return sorted(out)
