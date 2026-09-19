import sys as _sys

# Windows consoles default to cp1252 - any help/print containing non-ASCII
# (arrows, em dashes) raises UnicodeEncodeError and can crash --help.
# Harden stdout/stderr for every winre entry point.
for _stream in (_sys.stdout, _sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
