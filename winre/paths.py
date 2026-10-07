r"""paths.py - ONE authority for where evidence lives.

The defect this closes (found by running the code, not reading it):

Three modules each derived the evidence root independently:

    pipeline.py:59      Path(os.environ.get(WINRE_PIPELINE_LOGS) or (REPO/"logs")).resolve()
    remote_driver.py:47 Path(os.environ.get(WINRE_PIPELINE_LOGS, str(REPO/"logs")))
    ui/app.py:42        Path(remote_driver.LOCAL_LOGS)

The first calls `.resolve()` and coerces None to a default *inside* the
expression; the second does not resolve at all. With a real-world misconfigured
value (a paste into a UI box or a shell with a stray space):

    WINRE_PIPELINE_LOGS = "  D:\Has Space\logs  "
    pipeline  -> C:\...\WinRE\  D:\Has Space\logs      (resolve() of a non-path)
    driver    -> the raw unstripped value

The UI and the CLI then show DIFFERENT packs for the same run - the exact
split this function exists to prevent. A second, quieter instance of the same
class: `pipeline` read the env var at import time while `envfile` loads `.env`
at ITS import time, so ordering decided whether a `.env` value applied.

One call, one answer, computed after .env is loaded, stripped and resolved,
and shared by every entry point. Nothing may derive it again.
"""
from __future__ import annotations

import os
from pathlib import Path

ENV_KEY = "WINRE_PIPELINE_LOGS"
DEFAULT_ROOT_NAME = "logs"


def evidence_root() -> Path:
    """The local evidence root: `<repo>/logs` unless WINRE_PIPELINE_LOGS says
    otherwise. Stripped, resolved, and identical for every caller.

    Resolved against the repo root when relative, so a value like
    ``D:/evidence`` from a config file and one from the environment agree.
    """
    # import here, not at module top: envfile pulls .env into os.environ as a
    # side effect, and that must happen BEFORE we read the variable
    from winre import envfile
    envfile.load_dotenv()

    raw = (os.environ.get(ENV_KEY) or "").strip()
    if not raw:
        return (Path(__file__).resolve().parents[1] / DEFAULT_ROOT_NAME).resolve()

    # expand ~ and strip stray quotes a pasted value may carry
    for _ in range(4):                      # unwrap a quoted+spaced value
        _p = raw.strip().strip('"').strip("'").strip()
        if _p == raw:
            break
        raw = _p
    p = Path(os.path.expanduser(raw))
    if not p.is_absolute():
        p = (Path(__file__).resolve().parents[1] / p)
    return p.resolve()


def describe(root: Path) -> dict:
    """What a caller should tell a user about the configured root, including
    whether it is inside the repo (and therefore covered by .gitignore)."""
    repo = Path(__file__).resolve().parents[1]
    try:
        inside = root.resolve().is_relative_to(repo)
    except (OSError, ValueError):
        inside = False
    return {
        "root": str(root),
        "env_key": ENV_KEY,
        "inside_repo": inside,
        "gitignored": inside,          # .gitignore covers logs/ and internal/
        "warn": (None if inside else
                 "the configured evidence root is OUTSIDE this repository, so "
                 ".gitignore does not cover it: detonation artefacts there "
                 "(pcaps, memory dumps, extracted payloads) are not protected"),
    }