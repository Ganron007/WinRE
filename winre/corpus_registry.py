"""Content-addressed inventory and staging for malware corpora.

This module reads sample files as data. It never launches them. Registry output
is local operator state and should stay under the ignored ``internal/`` tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "winre-corpus-registry/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_ARCH = {
    0x014C: "x86", 0x8664: "x64", 0x01C0: "arm",
    0x01C4: "arm", 0xAA64: "arm64",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": SCHEMA, "updated_at": _now(), "samples": {}}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read registry {path}: {exc}") from exc
    if not isinstance(obj, dict) or obj.get("schema") != SCHEMA:
        raise ValueError(f"unsupported or invalid corpus registry: {path}")
    if not isinstance(obj.get("samples"), dict):
        raise ValueError("registry 'samples' must be an object keyed by SHA-256")
    return obj


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    obj["updated_at"] = _now()
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(obj, stream, indent=2, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _digest(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            h.update(block)
    return h.hexdigest(), size


def _classify(path: Path) -> dict[str, Any]:
    """Classify format from a small header; never trusts the filename alone."""
    suffix = path.suffix.lower()
    try:
        with path.open("rb") as stream:
            head = stream.read(16)
            if head.startswith(b"MZ"):
                stream.seek(0x3C)
                raw = stream.read(4)
                if len(raw) != 4:
                    return {"format": "dos_or_malformed", "architecture": "unknown",
                            "role": "unknown", "automatic_execution": False}
                pe_offset = int.from_bytes(raw, "little")
                if pe_offset < 0x40 or pe_offset > 64 * 1024 * 1024:
                    return {"format": "dos_or_malformed", "architecture": "unknown",
                            "role": "unknown", "automatic_execution": False}
                stream.seek(pe_offset)
                sig = stream.read(4)
                coff = stream.read(20)
                if sig != b"PE\0\0" or len(coff) != 20:
                    return {"format": "dos_or_malformed", "architecture": "unknown",
                            "role": "unknown", "automatic_execution": False}
                machine = int.from_bytes(coff[0:2], "little")
                optional_size = int.from_bytes(coff[16:18], "little")
                characteristics = int.from_bytes(coff[18:20], "little")
                magic = None
                if optional_size:
                    magic_raw = stream.read(2)
                    if len(magic_raw) == 2:
                        magic = int.from_bytes(magic_raw, "little")
                is_dll = bool(characteristics & 0x2000)
                role = ("driver_candidate" if suffix == ".sys" else
                        "library" if is_dll or suffix == ".dll" else
                        "executable_candidate")
                return {
                    "format": "pe32_plus" if magic == 0x20B else
                              "pe32" if magic == 0x10B else "pe_unknown_optional",
                    "architecture": _ARCH.get(machine, f"machine_0x{machine:04x}"),
                    "machine": f"0x{machine:04x}",
                    "characteristics": f"0x{characteristics:04x}",
                    "role": role,
                    "automatic_execution": False,
                    "execution_note": "PE type is a triage hint, not authorization to execute",
                }
            if head.startswith(b"%PDF-"):
                fmt = "pdf"
            elif head.startswith(b"PK\x03\x04"):
                fmt = "zip_container"
            elif head.startswith(bytes.fromhex("d0cf11e0a1b11ae1")):
                fmt = "ole_container"
            elif head.startswith(b"{\\rtf"):
                fmt = "rtf"
            elif head.startswith(b"#!"):
                fmt = "script"
            elif suffix in {".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd",
                            ".hta", ".wsf", ".wsh"}:
                fmt = "script_or_text"
            else:
                fmt = "unknown"
    except OSError as exc:
        return {"format": "unreadable", "architecture": "unknown", "role": "unknown",
                "automatic_execution": False, "classification_error": str(exc)}
    return {"format": fmt, "architecture": "unknown", "role": "non_pe_or_unknown",
            "automatic_execution": False,
            "execution_note": "non-PE content requires an explicit, reviewed launch plan"}


def _new_record(sha: str, size: int, facts: dict[str, Any], first_seen: str) -> dict[str, Any]:
    return {
        "sha256": sha, "size": size, **facts,
        "family": "unknown", "family_evidence": [],
        "first_seen": first_seen, "history_scope": "this_registry_only",
        "history_attestation": {"status": "unknown", "basis": None},
        "history_attestations": [],
        "aliases": [], "run_history": [], "staged_locations": [],
    }


def _merge_file(registry: dict[str, Any], path: Path, *, source_label: str,
                relative_path: str, source_path: str | None = None) -> str:
    sha, size = _digest(path)
    facts = _classify(path)
    record = registry["samples"].get(sha)
    if record is None:
        record = _new_record(sha, size, facts, _now())
        registry["samples"][sha] = record
    elif int(record.get("size", -1)) != size:
        raise ValueError(f"registry size conflicts with content hash {sha}")
    alias = {"source": source_label, "relative_path": relative_path,
             "filename": path.name}
    if source_path:
        alias["source_path"] = source_path
    aliases = record.setdefault("aliases", [])
    if alias not in aliases:
        aliases.append(alias)
    return sha


def inventory(source_root: Path, registry_path: Path, source_label: str) -> dict[str, Any]:
    source_root = Path(source_root)
    if source_root.is_symlink():
        raise ValueError("source root must not be a symlink")
    source_root = source_root.resolve(strict=True)
    if not source_root.is_dir():
        raise ValueError(f"source root is not a directory: {source_root}")
    if not source_label.strip():
        raise ValueError("source label must be non-empty")
    registry = _read_json(registry_path)
    visited = 0
    failures: list[dict[str, str]] = []
    registry_resolved = Path(registry_path).resolve()

    def on_walk_error(exc: OSError) -> None:
        failures.append({"path": str(getattr(exc, "filename", source_root)),
                         "error": str(exc)})

    for current, dirs, files in os.walk(source_root, followlinks=False,
                                        onerror=on_walk_error):
        current_path = Path(current)
        dirs[:] = sorted(d for d in dirs if not (current_path / d).is_symlink())
        for name in sorted(files):
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                continue
            if path.resolve() == registry_resolved:
                continue
            rel = path.relative_to(source_root).as_posix()
            try:
                _merge_file(registry, path, source_label=source_label,
                            relative_path=rel)
                visited += 1
            except (OSError, ValueError) as exc:
                failures.append({"path": rel, "error": str(exc)})
    registry["source_roots"] = registry.get("source_roots", [])
    root_record = {"label": source_label, "path": str(source_root)}
    if root_record not in registry["source_roots"]:
        registry["source_roots"].append(root_record)
    _write_json(registry_path, registry)
    return {"ok": not failures, "files_seen": visited, "samples": len(registry["samples"]),
            "failures": failures, "registry": str(registry_path)}


def stage_sample(source: Path, destination_root: Path, registry_path: Path,
                 source_label: str) -> dict[str, Any]:
    source = Path(source)
    if source.is_symlink():
        raise ValueError("source must not be a symlink")
    source = source.resolve(strict=True)
    if not source.is_file():
        raise ValueError("source must be a regular, non-symlink file")
    if not source_label.strip():
        raise ValueError("source label must be non-empty")
    registry = _read_json(registry_path)
    relative = source.name
    sha = _merge_file(registry, source, source_label=source_label,
                      relative_path=relative, source_path=str(source))
    record = registry["samples"][sha]
    destination = Path(destination_root).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    target_dir = destination / sha
    if target_dir.is_symlink():
        raise ValueError(f"staging hash directory must not be a symlink: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)
    if target_dir.resolve().parent != destination:
        raise ValueError(f"staging hash directory escaped its destination: {target_dir}")
    safe_name = re.sub(r"[^A-Za-z0-9._ -]", "_", source.name).strip(" .") or "sample.bin"
    if safe_name.split(".", 1)[0].upper() in {
            "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10))}:
        safe_name = f"sample_{safe_name}"
    target = target_dir / safe_name
    if target.is_symlink():
        raise ValueError(f"staging target must not be a symlink: {target}")
    if target.exists():
        existing_sha, _ = _digest(target)
        if existing_sha != sha:
            raise ValueError(f"staging target exists with different bytes: {target}")
    else:
        fd, temp_name = tempfile.mkstemp(prefix=".incoming-", dir=str(target_dir))
        os.close(fd)
        try:
            shutil.copyfile(source, temp_name)
            copied_sha, copied_size = _digest(Path(temp_name))
            if copied_sha != sha or copied_size != record["size"]:
                raise IOError("staged copy failed SHA-256/size verification")
            os.replace(temp_name, target)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
    staged = {"path": str(target), "sha256": sha, "verified_at": _now()}
    if staged not in record.setdefault("staged_locations", []):
        record["staged_locations"].append(staged)
    _write_json(registry_path, registry)
    return {"ok": True, "sha256": sha, "path": str(target),
            "format": record["format"], "architecture": record["architecture"],
            "role": record["role"], "automatic_execution": False}


def record_run(registry_path: Path, sha: str, *, mode: str, run_id: str,
               code_revision: str, config_digest: str, outcome: str,
               repeat_reason: str | None = None) -> dict[str, Any]:
    sha = sha.lower()
    if not SHA256_RE.fullmatch(sha):
        raise ValueError("sample identity must be a 64-character SHA-256")
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must be a 32-character control-plane nonce")
    if mode not in {"static", "agentic", "agentic-dbg"}:
        raise ValueError("mode must be static, agentic, or agentic-dbg")
    if outcome not in {"completed", "failed", "aborted"}:
        raise ValueError("outcome must be completed, failed, or aborted")
    if not code_revision.strip() or not config_digest.strip():
        raise ValueError("code revision and config digest are required")
    registry = _read_json(registry_path)
    record = registry["samples"].get(sha)
    if record is None:
        raise ValueError("sample is not in the registry; inventory it first")
    prior = [r for r in record.setdefault("run_history", []) if r.get("mode") == mode]
    if prior and not (repeat_reason and repeat_reason.strip()):
        raise ValueError(f"same-mode history already exists ({len(prior)} run(s)); "
                         "a repeat requires --repeat-reason")
    item = {"run_id": run_id.lower(), "mode": mode, "outcome": outcome,
            "code_revision": code_revision.strip(),
            "config_digest": config_digest.strip(), "recorded_at": _now()}
    if repeat_reason and repeat_reason.strip():
        item["repeat_reason"] = repeat_reason.strip()
    if any(r.get("run_id") == item["run_id"] for r in record["run_history"]):
        raise ValueError("run_id is already recorded for this sample")
    record["run_history"].append(item)
    _write_json(registry_path, registry)
    return {"ok": True, "run": item}


def attest_history(registry_path: Path, sha: str, *, status: str, operator: str,
                   basis: str, evidence_ref: str | None = None) -> dict[str, Any]:
    sha = sha.lower()
    if not SHA256_RE.fullmatch(sha):
        raise ValueError("sample identity must be a 64-character SHA-256")
    if status not in {"unknown", "no_recorded_winre_run_in_this_registry", "history_imported"}:
        raise ValueError("status must be unknown, no_recorded_winre_run_in_this_registry, "
                         "or history_imported")
    if not operator.strip() or not basis.strip():
        raise ValueError("operator and basis are required for an attestation")
    if status == "history_imported" and not (evidence_ref and evidence_ref.strip()):
        raise ValueError("history_imported requires an evidence reference")
    registry = _read_json(registry_path)
    record = registry["samples"].get(sha)
    if record is None:
        raise ValueError("sample is not in the registry; inventory it first")
    if status == "no_recorded_winre_run_in_this_registry" and record.get("run_history"):
        raise ValueError("cannot attest no recorded runs while this registry has run history")
    if (status == "history_imported"
            and not any((r.get("history_source") or {}).get("kind") == "imported"
                        for r in record.get("run_history", []))):
        raise ValueError("history_imported requires imported run records")
    attestation = {"status": status, "scope": "this_registry_only",
                   "operator": operator.strip(), "basis": basis.strip(),
                   "attested_at": _now()}
    if evidence_ref:
        attestation["evidence_ref"] = evidence_ref.strip()
    record["history_attestation"] = attestation
    record.setdefault("history_attestations", []).append(attestation)
    _write_json(registry_path, registry)
    return {"ok": True, "attestation": attestation}


def import_history(registry_path: Path, sha: str, history_file: Path, *,
                   operator: str, basis: str, evidence_ref: str) -> dict[str, Any]:
    """Import a structured history file without inferring absent fields.

    Expected document schema: ``winre-corpus-run-history/v1`` with matching
    ``sha256`` and a ``runs`` array. Legacy entries may omit run_id if they
    provide a stable legacy_id; missing timestamps/revisions remain null.
    """
    sha = sha.lower()
    if not SHA256_RE.fullmatch(sha):
        raise ValueError("sample identity must be a 64-character SHA-256")
    if not all(v.strip() for v in (operator, basis, evidence_ref)):
        raise ValueError("operator, basis and evidence reference are required")
    try:
        history_path = Path(history_file)
        source = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read history file: {exc}") from exc
    if (not isinstance(source, dict)
            or source.get("schema") != "winre-corpus-run-history/v1"
            or str(source.get("sha256", "")).lower() != sha
            or not isinstance(source.get("runs"), list)):
        raise ValueError("history file must use the supported schema and match the sample SHA-256")
    if not source["runs"]:
        raise ValueError("history file has no run records to import")
    history_sha, _history_size = _digest(history_path)
    registry = _read_json(registry_path)
    record = registry["samples"].get(sha)
    if record is None:
        raise ValueError("sample is not in the registry; inventory it first")
    history = record.setdefault("run_history", [])
    existing_ids = {str(item.get("run_id") or item.get("legacy_id")) for item in history}
    imported: list[dict[str, Any]] = []
    for raw in source["runs"]:
        if not isinstance(raw, dict):
            raise ValueError("each imported run must be an object")
        run_id = str(raw.get("run_id") or "").lower() or None
        legacy_id = str(raw.get("legacy_id") or "").strip() or None
        if run_id and not RUN_ID_RE.fullmatch(run_id):
            raise ValueError(f"invalid imported run_id: {run_id}")
        if not run_id and not legacy_id:
            raise ValueError("imported run requires run_id or stable legacy_id")
        mode = raw.get("mode")
        outcome = raw.get("outcome", "unknown")
        if mode not in {"static", "agentic", "agentic-dbg"}:
            raise ValueError(f"invalid imported mode: {mode}")
        if outcome not in {"completed", "failed", "aborted", "unknown"}:
            raise ValueError(f"invalid imported outcome: {outcome}")
        identity = run_id or legacy_id
        if identity in existing_ids:
            continue
        item = {
            "run_id": run_id, "legacy_id": legacy_id, "mode": mode,
            "outcome": outcome,
            "code_revision": raw.get("code_revision"),
            "config_digest": raw.get("config_digest"),
            "recorded_at": raw.get("recorded_at"),
            "history_source": {"kind": "imported", "evidence_ref": evidence_ref.strip(),
                               "history_file_sha256": history_sha,
                               "operator": operator.strip(), "basis": basis.strip()},
        }
        history.append(item)
        imported.append(item)
        existing_ids.add(identity)
    attestation = {"status": "history_imported", "scope": "this_registry_only",
                   "operator": operator.strip(), "basis": basis.strip(),
                   "evidence_ref": evidence_ref.strip(), "attested_at": _now()}
    record["history_attestation"] = attestation
    record.setdefault("history_attestations", []).append(attestation)
    _write_json(registry_path, registry)
    return {"ok": True, "imported": len(imported), "runs": imported,
            "attestation": attestation}


def classify_family(registry_path: Path, sha: str, *, family: str,
                    operator: str, basis: str, evidence_ref: str) -> dict[str, Any]:
    sha = sha.lower()
    if not SHA256_RE.fullmatch(sha):
        raise ValueError("sample identity must be a 64-character SHA-256")
    if not all(v.strip() for v in (family, operator, basis, evidence_ref)):
        raise ValueError("family, operator, basis and evidence reference are required")
    if family.strip().lower() == "unknown":
        raise ValueError("use inventory's unknown value until cited evidence supports a family")
    registry = _read_json(registry_path)
    record = registry["samples"].get(sha)
    if record is None:
        raise ValueError("sample is not in the registry; inventory it first")
    classification = {"family": family.strip(), "operator": operator.strip(),
                      "basis": basis.strip(), "evidence_ref": evidence_ref.strip(),
                      "recorded_at": _now()}
    evidence = record.setdefault("family_evidence", [])
    evidence.append(classification)
    current_family = str(record.get("family", "unknown")).casefold()
    if (current_family == "conflicting_evidence"
            or (current_family != "unknown" and current_family != family.strip().casefold())):
        record["family"] = "conflicting_evidence"
    elif current_family == "unknown":
        record["family"] = family.strip()
    _write_json(registry_path, registry)
    return {"ok": True, "classification": classification}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inventory, stage, and track corpus files by SHA-256")
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="hash files in an extracted corpus; never execute them")
    inv.add_argument("--source-root", required=True, type=Path)
    inv.add_argument("--source-label", required=True)
    inv.add_argument("--registry", type=Path, default=Path("internal/sample-registry.json"))

    stage = sub.add_parser("stage", help="copy one file into a hash-keyed directory and verify it")
    stage.add_argument("--source", required=True, type=Path)
    stage.add_argument("--destination-root", required=True, type=Path)
    stage.add_argument("--source-label", required=True)
    stage.add_argument("--registry", type=Path, default=Path("internal/sample-registry.json"))

    run = sub.add_parser("record-run", help="record an already completed/failed/aborted run")
    run.add_argument("--sha256", required=True)
    run.add_argument("--mode", required=True, choices=("static", "agentic", "agentic-dbg"))
    run.add_argument("--run-id", required=True)
    run.add_argument("--code-revision", required=True)
    run.add_argument("--config-digest", required=True)
    run.add_argument("--outcome", required=True, choices=("completed", "failed", "aborted"))
    run.add_argument("--repeat-reason")
    run.add_argument("--registry", type=Path, default=Path("internal/sample-registry.json"))

    att = sub.add_parser("attest-history", help="record scoped prior-run history knowledge")
    att.add_argument("--sha256", required=True)
    att.add_argument("--status", required=True,
                     choices=("unknown", "no_recorded_winre_run_in_this_registry", "history_imported"))
    att.add_argument("--operator", required=True)
    att.add_argument("--basis", required=True)
    att.add_argument("--evidence-ref")
    att.add_argument("--registry", type=Path, default=Path("internal/sample-registry.json"))

    imp = sub.add_parser("import-history", help="import cited, sample-bound run history")
    imp.add_argument("--sha256", required=True)
    imp.add_argument("--history-file", required=True, type=Path)
    imp.add_argument("--operator", required=True)
    imp.add_argument("--basis", required=True)
    imp.add_argument("--evidence-ref", required=True)
    imp.add_argument("--registry", type=Path, default=Path("internal/sample-registry.json"))

    family = sub.add_parser("classify-family", help="set a family only with cited evidence")
    family.add_argument("--sha256", required=True)
    family.add_argument("--family", required=True)
    family.add_argument("--operator", required=True)
    family.add_argument("--basis", required=True)
    family.add_argument("--evidence-ref", required=True)
    family.add_argument("--registry", type=Path, default=Path("internal/sample-registry.json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inventory":
            result = inventory(args.source_root, args.registry, args.source_label)
        elif args.command == "stage":
            result = stage_sample(args.source, args.destination_root, args.registry,
                                  args.source_label)
        elif args.command == "record-run":
            result = record_run(args.registry, args.sha256, mode=args.mode,
                                run_id=args.run_id, code_revision=args.code_revision,
                                config_digest=args.config_digest, outcome=args.outcome,
                                repeat_reason=args.repeat_reason)
        elif args.command == "attest-history":
            result = attest_history(args.registry, args.sha256, status=args.status,
                                    operator=args.operator, basis=args.basis,
                                    evidence_ref=args.evidence_ref)
        elif args.command == "import-history":
            result = import_history(args.registry, args.sha256, args.history_file,
                                    operator=args.operator, basis=args.basis,
                                    evidence_ref=args.evidence_ref)
        else:
            result = classify_family(args.registry, args.sha256, family=args.family,
                                     operator=args.operator, basis=args.basis,
                                     evidence_ref=args.evidence_ref)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("ok") else 2
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
