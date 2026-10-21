"""The UI, driven against a REAL evidence pack.

There were zero UI tests in this repo. Every route was exercised only by hand,
which is why the export route could ship a defect that a single request would
have exposed: it silently `continue`d past every file over 64 MB, so an analyst
exporting "the pack" received a 143-entry archive quietly missing 628 MB of
primary evidence (procmon.pml, both memory dumps, the case archive) with
nothing in it saying so.

These tests drive the Flask app through its test client over genuine packs on
disk. Packs are not all the same shape - some are legacy-flat with one mode,
some are sectioned with all four - so each test picks the pack that can answer
it and skips when no such pack exists. That keeps them honest in a clean
checkout instead of passing on fixtures.
"""
import io
import pathlib
import re
import zipfile

import pytest

from winre import evidence
from winre.ui.app import EXPORT_SIZE_CAP, LOGS_DIR, _section_root, create_app

REPO = pathlib.Path(__file__).resolve().parents[1]
LOGS = REPO / "logs"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _packs(logs_dir: pathlib.Path | None = None):
    """Every genuine pack: sha, root, whether it has a manifest, its modes."""
    logs_dir = logs_dir or LOGS
    out = []
    for p in logs_dir.rglob("dynamic"):
        if not p.is_dir() or (p / "deep").is_dir():
            continue
        sha = next((a.name for a in p.parents if HEX64.match(a.name)), None)
        if not sha:
            continue
        root = logs_dir / sha
        # Ignore orphaned nested trees (for example, interrupted test output
        # under logs/archive/<sha>/dynamic) rather than failing collection.
        if not root.is_dir():
            continue
        if root in [o["root"] for o in out]:
            continue
        out.append({
            "sha": sha,
            "root": root,
            "stage": p,
            "modes": sorted(d.name for d in root.iterdir()
                            if d.is_dir() and d.name in evidence.MODES),
            "manifest": (p / "manifest.json").is_file(),
        })
    return out


PACKS = _packs()
NEWEST = max(PACKS, key=lambda p: p["stage"].stat().st_mtime) if PACKS else None
MULTI = next((p for p in PACKS if len(p["modes"]) > 1), None)
WITH_MANIFEST = next((p for p in PACKS if p["manifest"]), None)

requires_pack = pytest.mark.skipif(
    not PACKS, reason="no real evidence pack in logs/ to drive the UI against")


def test_pack_discovery_skips_orphan_dynamic_tree(tmp_path):
    orphan = tmp_path / "archive" / ("b" * 64) / "dynamic"
    orphan.mkdir(parents=True)
    assert _packs(tmp_path) == []


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# ------------------------------------------------------- the read routes

@requires_pack
def test_every_read_route_renders(client):
    """A 500 is a broken product page, not a test failure."""
    for path in ("/", "/health", "/packs", "/help", "/mcp", "/settings",
                 "/api/gate", "/api/packs"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"


@requires_pack
def test_the_pack_page_renders_for_every_real_pack(client):
    """Every genuine pack must render. If one 500s, that is a regression the
    UI has never been checked for."""
    bad = []
    for pk in PACKS:
        r = client.get(f"/packs/{pk['sha']}")
        if r.status_code != 200:
            bad.append(f"{pk['sha'][:12]}: {r.status_code}")
    assert not bad, f"pack pages that fail: {bad}"


@requires_pack
def test_the_pack_page_shows_the_evidence_not_an_empty_shell(client):
    """A page that renders 200 while showing nothing is the UI version of a
    green run with no evidence.

    The probes follow the pack's own modes: a pack with a dynamic run must
    show the detonation artifacts, a static-only pack has none by definition
    and must show ITS evidence instead (the technical report, the capa
    capability set, the verdict).  Probing a static pack for Procmon/Frida
    asserted the presence of evidence the run never produced.
    """
    body = client.get(f"/packs/{NEWEST['sha']}").get_data(as_text=True)
    if "dynamic" in NEWEST["modes"]:
        probes = ("Procmon", "Frida", "procmon.csv")
    else:
        probes = ("REPORT-TECHNICAL", "capa", "verdict")
    for probe in probes:
        assert probe in body, f"the pack page does not show {probe!r}"


@requires_pack
def test_no_template_errors_on_any_pack_page(client):
    bad = []
    for pk in PACKS:
        body = client.get(f"/packs/{pk['sha']}").get_data(as_text=True)
        for err in ("jinja2", "TemplateNotFound", "UndefinedError",
                    "BuildError"):
            if err in body:
                bad.append(f"{pk['sha'][:12]}: {err}")
    assert not bad, f"template errors: {bad}"


@requires_pack
def test_health_reports_the_evidence_root(client):
    import json
    data = json.loads(client.get("/health").get_data(as_text=True))
    assert "ssh" in data and "logs_dir" in data, data


# ------------------------------------------------------------- the export

@requires_pack
def test_export_is_a_real_zip(client):
    r = client.get(f"/packs/{NEWEST['sha']}/export")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.get_data()))
    assert len(z.namelist()) > 10, "the export is nearly empty"


@pytest.mark.skipif(not MULTI, reason="no multi-mode pack on disk")
def test_export_carries_every_mode_the_pack_has(client):
    """The export root is the whole pack, so each producer section that exists
    on disk must be in the archive - and only those that exist."""
    r = client.get(f"/packs/{MULTI['sha']}/export")
    names = set(zipfile.ZipFile(io.BytesIO(r.get_data())).namelist())
    for mode in MULTI["modes"]:
        assert any(n.startswith(f"{mode}/") for n in names), (
            f"mode {mode} exists on disk but is absent from the export")
    for mode in evidence.MODES:
        if mode not in MULTI["modes"]:
            assert not any(n.startswith(f"{mode}/") for n in names), (
                f"the export contains {mode}/ which is not in this pack")


@pytest.mark.skipif(not WITH_MANIFEST, reason="no pack with a manifest on disk")
def test_export_carries_the_manifest(client):
    r = client.get(f"/packs/{WITH_MANIFEST['sha']}/export")
    names = set(zipfile.ZipFile(io.BytesIO(r.get_data())).namelist())
    assert any(n.endswith("manifest.json") for n in names), (
        "the manifest exists on disk but is not in the export")


@requires_pack
def test_export_never_drops_a_file_in_silence(client):
    """The defect this replaces: `continue` past every >64MB file with no
    record, so a 143-entry archive was quietly missing 628 MB of primary
    evidence and said nothing about it.

    The cap stays - a 500 MB download is not what an export button is for -
    but the gap must be named, inside the archive and in the headers.
    """
    r = client.get(f"/packs/{NEWEST['sha']}/export")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.get_data()))
    names = set(z.namelist())

    skipped = int(r.headers.get("X-WinRE-Export-Skipped", "0"))
    embedded = int(r.headers.get("X-WinRE-Export-Embedded", "0"))
    assert embedded == len(names) - (1 if skipped else 0), (
        "the header count does not match the archive")

    if skipped == 0:
        return                      # nothing was capped: nothing to record

    # 1. the record is INSIDE the archive
    assert "EXPORT-NOT-EMBEDDED.txt" in names, (
        "files were skipped and the archive does not say so")
    note = z.read("EXPORT-NOT-EMBEDDED.txt").decode("utf-8")

    # 2. the byte count is reported and non-zero
    skipped_bytes = r.headers.get("X-WinRE-Export-Skipped-Bytes")
    assert skipped_bytes and int(skipped_bytes) > 0

    # 3. and the note must not read as "this evidence does not exist"
    for phrase in ("only because of their size", "NOT in this archive"):
        assert phrase in note, f"the note does not say why: {phrase!r}"


@requires_pack
def test_the_export_record_is_accurate_against_the_disk(client):
    """The record must match reality: every file over the cap on disk must be
    named in it, and must NOT also be in the archive."""
    r = client.get(f"/packs/{NEWEST['sha']}/export")
    z = zipfile.ZipFile(io.BytesIO(r.get_data()))
    names = set(z.namelist())
    root = _section_root(NEWEST["sha"], None).resolve()

    over = [f for f in root.rglob("*")
            if f.is_file() and f.stat().st_size > EXPORT_SIZE_CAP]
    if not over:
        pytest.skip("nothing over the cap in this pack")
    assert "EXPORT-NOT-EMBEDDED.txt" in names, (
        "files over the cap exist on disk and the archive does not name them")
    note = z.read("EXPORT-NOT-EMBEDDED.txt").decode("utf-8")
    for f in over:
        rel = str(f.relative_to(root))
        assert rel in note or rel.replace("/", "\\") in note, (
            f"{rel} is over the cap on disk but is not in the record")
        assert rel not in names and rel.replace("/", "\\") not in names, (
            f"{rel} is named as skipped but IS in the archive")


def test_export_cap_is_configurable_and_positive():
    assert EXPORT_SIZE_CAP > 0


# --------------------------------------------------- the per-file route

@requires_pack
def test_the_file_route_serves_real_evidence(client):
    for fname in ("procmon.csv", "META.json", "manifest.json"):
        r = client.get(f"/packs/{NEWEST['sha']}/dynamic/{fname}")
        if r.status_code == 404:
            continue                # not every pack has every file
        assert r.status_code == 200, f"{fname}: {r.status_code}"


@requires_pack
def test_the_file_route_refuses_traversal(client):
    """The file route must not be a path-traversal hole."""
    r = client.get(f"/packs/{NEWEST['sha']}/dynamic/..%5C..%5Cwinre%5Capp.py")
    assert r.status_code in (400, 404), f"traversal returned {r.status_code}"


@requires_pack
def test_a_bad_sha_is_refused_not_silently_handled(client):
    r = client.get("/packs/not-a-sha/export")
    assert r.status_code == 400
