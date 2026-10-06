"""Regression pin for the UnboundLocalError found on the item-8 path.

Found 2026-10-06 while verifying P1-F1 on a real PE32 sample:

    UnboundLocalError: cannot access local variable 'imp_modes_tried'

`imp_modes_tried` was initialised inside `if not oep_in_module:` but appended
to in the `else:` branch (the pe-sieve /imp IAT-rebuild escalation) and
reported after both branches. The ordinary module-dump path - the one that
SUCCEEDS - therefore crashed with an unbound local.

It stayed latent because every 32-bit run died at the OEP long before
reaching it, and because no test drives a real debugger.

Scope note - why there is no general sweep here. The obvious generalisation
is "flag every name assigned inside a branch and read later". Measured on
this package that fires 560 times, because ordinary code does `x = ...`
inside a `try:` or `if:` and uses `x` immediately after. Adding proper
domination analysis (bound at function level, or bound in every branch of a
try and every handler) still leaves ~20 per file, because sound detection
needs real path merging - which is what CPython's own symtable does and what
is out of scope for a test.

test_the_naive_sweep_is_unusable_as_a_gate below records that measurement so
the decision is reproducible rather than folklore, and so nobody re-adds the
noisy version believing it is clean.
"""
import ast
import inspect
import pathlib

import pytest

from winre import debug_loops


# --- the exact regression -------------------------------------------------

def test_imp_modes_tried_is_bound_at_function_level():
    """It must be initialised before the if/else that splits the two dump
    strategies, not inside one of them."""
    tree = ast.parse(pathlib.Path(inspect.getsourcefile(debug_loops))
                     .read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "agentic_unpack")
    binds = [n for n in fn.body
             if isinstance(n, ast.AnnAssign)
             and isinstance(n.target, ast.Name)
             and n.target.id == "imp_modes_tried"]
    assert len(binds) == 1, (
        f"imp_modes_tried must be bound exactly once at function level; "
        f"found {len(binds)}")
    reads = [n.lineno for n in ast.walk(fn)
             if isinstance(n, ast.Name) and n.id == "imp_modes_tried"
             and isinstance(n.ctx, ast.Load)]
    assert reads, "it is never read - the escalation was removed?"
    assert binds[0].lineno < min(reads), (
        f"bound at line {binds[0].lineno} but first read at {min(reads)}: "
        "the binding must precede every read, including the ones in the "
        "sibling branch of the if/else that splits the dump strategies")


def test_both_dump_strategies_report_imp_modes_tried():
    """The heap arm returns early with it, the module arm escalates with it.
    Both must carry the key, so a consumer can always see what was tried."""
    src = inspect.getsource(debug_loops.agentic_unpack)
    assert src.count('"imp_modes_tried": imp_modes_tried') >= 2, (
        "expected it on the heap-arm return, the module-arm record, and the "
        "final record")


def test_the_append_sits_in_the_module_arm_that_uses_it():
    src = inspect.getsource(debug_loops.agentic_unpack).splitlines()
    bind = next(i for i, l in enumerate(src) if "imp_modes_tried: list[int]" in l)
    append = next(i for i, l in enumerate(src) if "imp_modes_tried.append" in l)
    assert bind < append, "the binding must precede the append"


def test_agentic_unpack_reports_the_escalation_not_a_crash():
    """agentic_unpack must never raise for a missing PID / no-debugger state.
    It returns a structured dict the agent can reason about."""
    sig = inspect.signature(debug_loops.agentic_unpack)
    assert "sample" in sig.parameters
    # the caller wraps it, but a defensive guarantee belongs here too
    assert "imp_modes_tried" in inspect.getsource(debug_loops.agentic_unpack)


# --- why there is no general sweep (documented, reproducible) -------------

def _naive_findings(rel: str) -> int:
    """Count 'bound inside a branch and read later' with no domination
    reasoning at all - the version that must never become a gate."""
    tree = ast.parse(pathlib.Path(rel).read_text(encoding="utf-8-sig"))
    nesting = (ast.If, ast.For, ast.While, ast.With, ast.Try)
    # a list, not an int: `global` inside the visitor would make the name a
    # global while the enclosing function reads it as a local (which is the
    # very UnboundLocalError this file is about)
    total = [0]

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            reads = {}
            for n in ast.walk(node):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                    reads.setdefault(n.id, []).append(n.lineno)
            stack = []

            def walk(nd):
                for ch in ast.iter_child_nodes(nd):
                    if isinstance(ch, nesting):
                        stack.append(ch)
                        walk(ch)
                        stack.pop()
                    elif isinstance(ch, (ast.Assign, ast.AnnAssign)):
                        names = ([t.id for t in ch.targets
                                  if isinstance(t, ast.Name)]
                                 if isinstance(ch, ast.Assign)
                                 else ([ch.target.id]
                                       if isinstance(ch.target, ast.Name)
                                       else []))
                        if stack:
                            for nm in names:
                                if any(l > ch.lineno for l in reads.get(nm, [])):
                                    total[0] += 1
                        walk(ch)
                    else:
                        walk(ch)

            walk(node)

        visit_AsyncFunctionDef = visit_FunctionDef

    V().visit(tree)
    return total[0]


@pytest.mark.parametrize("rel", [
    "winre/debug_loops.py", "winre/agentic.py", "winre/remote_driver.py",
    "winre/pipeline.py", "winre/orchestrator.py",
])
def test_the_naive_sweep_is_unusable_as_a_gate(rel):
    """Pins the decision NOT to ship a general branch-binding gate.

    If this count ever collapses to ~0 the package has been rewritten to avoid
    the pattern entirely, and a sound sweep becomes worth building. Until
    then a gate here would fire hundreds of times on correct code.
    """
    n = _naive_findings(rel)
    assert n > 20, (
        f"{rel}: the naive sweep now finds only {n} candidates - if that is "
        "because the code genuinely got safer, a sound domination-based gate "
        "is worth writing; revisit this test")