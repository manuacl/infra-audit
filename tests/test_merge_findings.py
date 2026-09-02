#!/usr/bin/env python3
"""Regression tests for merge-findings.py. No dependency, no test runner:

    python3 tests/test_merge_findings.py

The merge is the one piece of this skill that rewrites a file the owner has
been annotating for weeks. Everything here exists because a real re-audit
produced a wrong report, not because a rule said to write tests.
"""
import json
import sys
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "infra-audit" / "scripts"))
merge_mod = __import__("merge-findings".replace("-", "_")) if False else None

import importlib.util
spec = importlib.util.spec_from_file_location(
    "merge_findings", ROOT / "skills" / "infra-audit" / "scripts" / "merge-findings.py"
)
mf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mf)

spec_r = importlib.util.spec_from_file_location(
    "render_report", ROOT / "skills" / "infra-audit" / "scripts" / "render-report.py"
)
rr = importlib.util.module_from_spec(spec_r)
spec_r.loader.exec_module(rr)

TODAY = "2026-09-02"
FAILURES = []


def check(name, cond, detail=""):
    print(f"  {'ok  ' if cond else 'FAIL'}  {name}")
    if not cond:
        FAILURES.append(f"{name}: {detail}")


def finding(fid, key, order, status="todo", severity="P3", title=None):
    return {"id": fid, "key": key, "order": order, "status": status,
            "severity": severity, "title": title or key.upper()}


def run(old_findings, new_findings):
    old = {"meta": {"date": "2026-01-01"}, "findings": old_findings}
    new = {"meta": {"date": TODAY}, "findings": new_findings}
    merged, report = mf.merge(old, new, TODAY)
    return merged, report, {f["key"]: f for f in merged["findings"]}


def test_incumbent_keeps_its_id():
    """A pass numbered from scratch reuses F1/F2 for different findings.

    The owner refers to a finding by its id, in notes and in tickets, so the
    finding already in the report keeps it and the newcomer is renamed. The
    first real re-audit got this backwards and shipped two findings called F2.
    """
    merged, report, by_key = run(
        [finding("F1", "a", 1, status="fixed"), finding("F2", "b", 2)],
        [finding("F1", "c", 1), finding("F2", "b", 2)],
    )
    check("incumbent A keeps F1", by_key["a"]["id"] == "F1", by_key["a"]["id"])
    check("incumbent B keeps F2", by_key["b"]["id"] == "F2", by_key["b"]["id"])
    check("newcomer C was renamed", by_key["c"]["id"] not in ("F1", "F2"), by_key["c"]["id"])
    check("rename was reported", len(report["renumbered"]) == 1, report["renumbered"])


def test_ids_and_ranks_are_unique():
    """No two findings may share an id, and no two rows may show the same rank.

    A duplicate rank is what the owner sees first: two rows both labelled #3.
    """
    merged, _, _ = run(
        [finding("F1", "a", 1), finding("F2", "b", 2), finding("F3", "c", 3)],
        [finding("F1", "d", 1), finding("F2", "e", 2), finding("F3", "c", 3)],
    )
    ids = [f["id"] for f in merged["findings"]]
    orders = sorted(f["order"] for f in merged["findings"])
    check("ids unique", len(set(ids)) == len(ids), ids)
    check("ranks unique and contiguous", orders == list(range(1, len(orders) + 1)), orders)


def test_incumbent_wins_the_rank_tie():
    """A newcomer arriving at order 1 must not displace the plan's first item."""
    merged, _, _ = run(
        [finding("F1", "a", 1), finding("F2", "b", 2)],
        [finding("F1", "z", 1)],
    )
    first = min(merged["findings"], key=lambda f: f["order"])
    check("plan's first item stays first", first["key"] == "a", first["key"])


def test_fixed_finding_that_reappears_is_a_regression():
    """This outranks a new finding: something closed came back."""
    merged, report, by_key = run(
        [finding("F1", "a", 1, status="fixed", title="A")],
        [finding("F1", "a", 1, title="A")],
    )
    check("status reverted to todo", by_key["a"]["status"] == "todo", by_key["a"]["status"])
    check("reported as a regression", report["regressed"] == ["A"], report["regressed"])
    check("REGRESSION named in the notes", "REGRESSION" in by_key["a"]["notes"])


def test_absent_from_a_pass_is_never_auto_closed():
    """A collector may simply have failed. Absence is not proof of a fix."""
    merged, report, by_key = run(
        [finding("F1", "a", 1), finding("F2", "b", 2)],
        [finding("F1", "a", 1)],
    )
    check("still open", by_key["b"]["status"] == "todo", by_key["b"]["status"])
    check("flagged as unseen", report["unseen"] == [by_key["b"]["title"]], report["unseen"])
    check("note says to verify by hand", "Non observe" in by_key["b"]["notes"])


def test_settled_and_absent_stays_silent():
    """The normal case: a fixed finding gone from the next pass is not news."""
    merged, report, by_key = run(
        [finding("F1", "a", 1, status="fixed"), finding("F2", "b", 2, status="accepted")],
        [],
    )
    check("fixed stays fixed", by_key["a"]["status"] == "fixed")
    check("accepted stays accepted", by_key["b"]["status"] == "accepted")
    check("neither reported as unseen", report["unseen"] == [], report["unseen"])


def test_status_and_notes_survive_a_refresh():
    """The point of merging rather than replacing: the follow-up is not lost."""
    old = finding("F1", "a", 1, status="in_progress")
    old["notes"] = "en cours depuis mardi"
    old["evidence"] = "ancienne preuve"
    new = finding("F1", "a", 9)
    new["evidence"] = "preuve fraiche"
    merged, _, by_key = run([old], [new])
    check("status kept", by_key["a"]["status"] == "in_progress", by_key["a"]["status"])
    check("notes kept", by_key["a"]["notes"] == "en cours depuis mardi")
    check("evidence refreshed", by_key["a"]["evidence"] == "preuve fraiche")


def test_no_internal_flag_leaks_into_the_file():
    """The merge tags incumbents while it works; that must not reach the disk."""
    merged, _, _ = run([finding("F1", "a", 1)], [finding("F1", "b", 1)])
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "out.json"
        p.write_text(json.dumps(merged, ensure_ascii=False))
        raw = p.read_text()
    check("_incumbent absent from the output", "_incumbent" not in raw)


def test_plan_lint_catches_a_buried_p1():
    """A P1 ranked below lighter findings contradicts the list's own heading.

    Reported by an owner reading the first real report: the worst finding sat
    at rank #10 with no argument for it anywhere on the page.
    """
    findings = [
        finding("F1", "a", 1, severity="P2"),
        finding("F2", "b", 2, severity="P4"),
        finding("F3", "c", 3, severity="P1"),
    ]
    warns = rr.lint_plan(findings)
    check("buried P1 is flagged", any("F3 (P1)" in w for w in warns), warns)

    findings[2]["order"], findings[0]["order"] = 1, 3
    check("silent once the P1 leads", rr.lint_plan(findings) == [], rr.lint_plan(findings))


def test_render_sinks_settled_work_to_the_bottom():
    """Closed findings render last, in the priority order they were closed in.

    The generator does this rather than warning the author about it: a fix
    session closes items in whatever order the plan dictates, and the report
    is read for what is left. The rank badge is NOT renumbered, so a settled
    #1 keeps its number at the bottom and the open list starts at #2.
    """
    findings = [
        finding("F1", "closed first", 1, status="fixed", severity="P1"),
        finding("F2", "still open", 2, severity="P2"),
        finding("F3", "accepted", 3, status="accepted", severity="P3"),
        finding("F4", "open too", 4, severity="P3"),
    ]
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "r.html"
        rr.render({"meta": {}, "findings": findings}, out)
        html = out.read_text(encoding="utf-8")

    ranks = re.findall(r'class="ord">#(\d+)', html)
    check("open findings come first, settled last", ranks == ["2", "4", "1", "3"], ranks)

    # Anchor on the rank badge, not on the bare "#1": the stylesheet is full
    # of hex colours and html.index("#2") lands in the CSS block.
    sep = html.index('class="sep"')
    first_open = html.index('class="ord">#2')
    first_settled = html.index('class="ord">#1')
    check("the divider sits between the two groups",
          first_open < sep < first_settled, (first_open, sep, first_settled))

    # Ranks are the author's, not the renderer's: renumbering them would erase
    # where a closed finding stood when it mattered.
    check("ranks are not renumbered", "#1" in html and "#3" in html, ranks)


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        print(f"\n{t.__name__}")
        summary = (t.__doc__ or "").strip().splitlines()
        if summary:
            print(f"  {summary[0]}")
        t()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print("  -", f)
        sys.exit(1)
    print(f"all checks passed ({len(tests)} tests)")


if __name__ == "__main__":
    main()
