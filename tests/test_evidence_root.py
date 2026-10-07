"""One authority for the evidence root, and it must hold for every input.

The defect, found by RUNNING the code: pipeline.py called `.resolve()` and
coerced None inside the expression; remote_driver.py did neither. With a
paste into a UI config box or a shell carrying whitespace, the two resolved
to different roots, so the UI and the CLI showed different packs for the same
run. Both modules now delegate to `winre.paths`, and these tests prove they
agree for real inputs rather than only for a tidy one.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BAD = "  D:" + chr(92) + "Has Space" + chr(92) + "logs  "
GOOD = "D:" + chr(92) + "evidence" + chr(92) + "logs"


def _fresh(root=None):
    """Reload the winre modules with a clean env, so import-time resolution
    is re-exercised (the quiet instance of this bug was an import-order one:
    pipeline read the env var at import while envfile loads .env at its)."""
    for m in [k for k in sys.modules if k.startswith("winre")]:
        del sys.modules[m]
    if root is not None:
        os.environ["WINRE_PIPELINE_LOGS"] = root
    else:
        os.environ.pop("WINRE_PIPELINE_LOGS", None)
    from winre import pipeline, paths, remote_driver
    from winre.ui import app
    return paths, pipeline, remote_driver, app


def test_the_default_root_is_inside_the_repo():
    paths, pipeline, driver, app = _fresh()
    expected = (REPO / "logs").resolve()
    assert paths.evidence_root() == expected
    assert pipeline.LOGS_DIR == expected
    assert driver.LOCAL_LOGS == expected
    assert app.LOGS_DIR == expected


def test_all_three_entry_points_agree():
    """One input, one answer, three consumers. This is the whole regression."""
    paths, pipeline, driver, app = _fresh(GOOD)
    roots = {str(pipeline.LOGS_DIR), str(driver.LOCAL_LOGS),
             str(app.LOGS_DIR), str(paths.evidence_root())}
    assert len(roots) == 1, roots


def test_whitespace_is_stripped_rather_than_resolved_into_a_bogus_path():
    """resolve() of a padded non-path yields <repo> plus the raw text, which
    cannot exist. Stripping is the only correct reading."""
    paths, _, _, _ = _fresh(BAD)
    got = str(paths.evidence_root())
    assert got == BAD.strip(), got
    assert not got.startswith(str(REPO)), got


def test_quotes_a_pasted_value_carries_are_stripped():
    paths, _, _, _ = _fresh('"  ' + GOOD + '  "')
    assert str(paths.evidence_root()) == GOOD


def test_relative_paths_resolve_against_the_repo():
    paths, _, _, _ = _fresh("my-evidence")
    assert str(paths.evidence_root()) == str((REPO / "my-evidence").resolve())


def test_a_root_outside_the_repo_is_flagged():
    """Evidence that is pcaps and memory dumps must not silently escape
    .gitignore."""
    from winre.paths import describe
    d = describe(Path("D:/evidence/logs"))
    assert d["inside_repo"] is False
    assert d["gitignored"] is False
    assert d["warn"] and "OUTSIDE" in d["warn"]


def test_a_root_inside_the_repo_is_not_flagged():
    from winre.paths import describe
    d = describe(REPO / "logs")
    assert d["inside_repo"] is True and d["gitignored"] is True
    assert d["warn"] is None


def test_an_empty_or_blank_value_falls_back_to_the_default():
    for blank in ("", "   "):
        paths, _, _, _ = _fresh(blank)
        assert paths.evidence_root() == (REPO / "logs").resolve(), blank


def test_the_ui_does_not_read_the_env_var_itself():
    src = (REPO / "winre" / "ui" / "app.py").read_text(encoding="utf-8")
    assert "LOGS_DIR = Path(remote_driver.LOCAL_LOGS)" in src
    body = "\n".join(l for l in src.splitlines()
                     if "local evidence root" not in l)
    assert "WINRE_PIPELINE_LOGS" not in body, (
        "the UI must delegate, not re-derive")


def test_no_module_derives_the_root_independently():
    """A fourth derivation would start the whole problem again."""
    for rel in ("winre/pipeline.py", "winre/remote_driver.py", "winre/ui/app.py"):
        src = (REPO / rel).read_text(encoding="utf-8")
        for form in ('os.environ.get("WINRE_PIPELINE_LOGS"',
                     "os.environ.get('WINRE_PIPELINE_LOGS'"):
            assert form not in src, f"{rel}: reads the env var directly"
        assert ("evidence_root" in src) or ("LOCAL_LOGS" in src), (
        f"{rel}: does not use the authority")


def test_the_env_var_really_controls_it_out_of_process():
    """Import-time behaviour, verified in a subprocess so a parent's earlier
    imports cannot mask a difference."""
    code = ("import os,sys;os.environ['WINRE_PIPELINE_LOGS']=sys.argv[1];"
            "from winre import paths;print(paths.evidence_root())")
    out = subprocess.run([sys.executable, "-c", code, BAD],
                         capture_output=True, text=True, cwd=str(REPO))
    assert out.stdout.strip() == BAD.strip(), out.stdout + out.stderr
