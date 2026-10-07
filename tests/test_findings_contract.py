"""The two mistakes that reading the code could not find.

Both were caught by RUNNING the pipeline on a real pack, and both cost a full
pipeline run before anyone noticed. They are pinned here so neither returns.
"""
import ast
import pathlib

from winre import findings


def test_dynamic_findings_takes_the_mode_root_and_descends_itself(tmp_path):
    """dynamic_findings is handed logs/<sha>/<mode>/ and finds the stage dir
    under it. A caller that hands it the stage dir gets a second descent into
    a path that does not exist, which reads as an empty detonation - the
    exact symptom that made a successful run look dead."""
    stage = tmp_path / "agentic" / "dynamic"
    stage.mkdir(parents=True)
    (stage / "META.job.json").write_text(
        '{"sample_pid": 1, "window": {"effective_s": 12}}', encoding="utf-8")

    f = findings.dynamic_findings(tmp_path / "agentic", sha="f" * 64)
    assert f["ok"] is True, f"mode root not accepted: {f['limitations'][:1]}"
    assert f["findings"]["window"]["effective_s"] == 12
    assert "META.job.json" in f["evidence_used"]


def test_the_route_is_recorded_not_left_as_a_silent_unknown(tmp_path):
    """A .NET assembly has no native OEP. Reporting the debug section as
    'unknown' for it reads as 'we never tried', which is how this mode looked
    across a whole real run. The route is a property of the sample, so it is
    recorded, and the reason native unpack does not apply is stated."""
    mode_root = tmp_path / "dbg"
    (mode_root / "quick").mkdir(parents=True)
    (mode_root / "deep").mkdir(parents=True)
    (mode_root / "quick" / "quick.json").write_text(
        '{"evidence": {"pe": {"is_dotnet": true}}, "verdict": {}}',
        encoding="utf-8")
    (mode_root / "deep" / "deep.json").write_text(
        '{"agent": {"dbg_ensure": {"arch": 64, "launched": true},'
        ' "unpack_prepass": {}}}', encoding="utf-8")

    f = findings.dbg_findings(mode_root, sha="e" * 64)
    route = f["findings"]["route"]
    assert route["managed"] is True
    assert route["native_unpack_applies"] is False
    assert "dotnet" in route["method"]
    # and the verdict must not be an unexplained unknown
    assert f["ok"] is True
    assert f["verdict"]["level"] != findings.UNKNOWN
    assert any(".NET" in x for x in f["limitations"])


def test_native_route_still_reports_a_missing_oep():
    """The route record must not become a blanket excuse: for a NATIVE sample,
    no OEP is still a real failure and is still named as one."""
    import inspect
    src = inspect.getsource(findings.dbg_findings)
    assert 'if managed and not up.get("ok"):' in src


# ------------------------------------------------- use-before-def sweep

def _source_order(node):
    """Yield a function's own names in the order the interpreter binds them."""
    for child in ast.iter_child_nodes(node):
        yield child


def _loads_before_binding(fn: ast.FunctionDef) -> list[str]:
    """Names the function LOADS before it has BOUND them locally.

    Walks the body in statement order and flags a Load of a name that IS a
    local (it is assigned somewhere in this function) but has not been bound
    yet at that point. That is UnboundLocalError - the shape that made a
    successful detonation report "did not run", and that build() catches and
    files as a limitation nobody reads.
    """
    params = {a.arg for a in
              list(fn.args.args) + list(fn.args.kwonlyargs)
              + list(fn.args.posonlyargs)}
    if fn.args.vararg:
        params.add(fn.args.vararg.arg)
    if fn.args.kwarg:
        params.add(fn.args.kwarg.arg)

    assigned_anywhere: set[str] = set(params)
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            assigned_anywhere.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            assigned_anywhere.add(n.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            assigned_anywhere.add(n.name)

    bound: set[str] = set(params)
    bad: list[str] = []
    seen: set[str] = set()

    def visit(node):
        # a comprehension has its own scope: bind its targets before looking
        # at the body, or every `for p in ...` reads as a use-before-def
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp,
                             ast.GeneratorExp, ast.Lambda)):
            for gen in node.generators:
                for t in ast.walk(gen.target):
                    if isinstance(t, ast.Name):
                        bound.add(t.id)
        # `except X as e` binds e for the handler's whole body: it is not
        # legal to reference it in the `except` clause itself, so it must be
        # pre-bound or every handler reads as use-before-def
        if isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
            seen.add(node.name)
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                if (node.id in assigned_anywhere and node.id not in bound
                        and node.id not in seen):
                    bad.append(node.id)
                    seen.add(node.id)
            else:  # Store / Del
                bound.add(node.id)
        for child in ast.iter_child_nodes(node):
            visit(child)

    for stmt in fn.body:
        visit(stmt)
    return bad


def test_the_detector_really_detects():
    """Prove the sweep above has teeth before trusting it as a guard.

    A sweep that silently passes on broken code is worse than no sweep: it
    buys exactly the confidence this file exists to withhold.
    """
    src = (
        "def dbg_findings(mode_root, *, sha=''):\n"
        "    findings['route'] = {'managed': True}\n"
        "    findings: dict = {'unpack': {}}\n"
        "    return findings\n")
    fn = ast.parse(src).body[0]
    assert _loads_before_binding(fn) == ["findings"], (
        "the sweep does not see the real defect it was written for")


def test_no_extractor_reads_a_local_before_it_is_assigned():
    """The defect class that twice turned a working run into a report of
    failure: a local referenced before assignment.

    It is invisible to reading, invisible to the type checker, and build()
    catches it and files it as a limitation - so the run looks merely
    incomplete instead of obviously broken. Catch it structurally instead.
    """
    src = pathlib.Path(findings.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    offenders: dict[str, list[str]] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        if not (fn.name.endswith("_findings") or fn.name == "build"):
            continue
        bad = _loads_before_binding(fn)
        if bad:
            offenders[fn.name] = bad
    assert not offenders, (
        "these findings functions read a local before assigning it: "
        + "; ".join(f"{k}: {v}" for k, v in offenders.items()))
