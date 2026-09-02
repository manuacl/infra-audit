#!/usr/bin/env python3
"""Merge a fresh audit pass into an existing report, preserving the follow-up.

A re-audit must never cost you the record of what was already done. This
merges a new findings file into the existing one and keeps status and notes,
with one rule that matters more than the others: a finding previously marked
fixed that shows up again is a REGRESSION, not a new finding.

Usage: merge-findings.py <existing.json> <new.json> [-o merged.json]
       (default: rewrites <existing.json> in place, after a .bak copy)

Matching is by the `key` field when present, else by a slug of the title.
Give a finding an explicit stable `key` when its wording may change between
runs - the key is what survives a rewrite.
"""
import json
import re
import shutil
import sys
from datetime import date
from pathlib import Path

SETTLED = ("fixed", "accepted")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:60]


def key_of(f):
    return f.get("key") or slug(f.get("title", ""))


def merge(old, new, today):
    old_by_key = {key_of(f): f for f in old.get("findings", [])}
    new_by_key = {key_of(f): f for f in new.get("findings", [])}

    merged, report = [], {"kept": [], "new": [], "regressed": [], "unseen": []}

    for k, nf in new_by_key.items():
        of = old_by_key.get(k)
        if of is None:
            nf.setdefault("status", "todo")
            nf["notes"] = (nf.get("notes") or "") + f" [Nouveau constat, {today}.]"
            merged.append(nf)
            report["new"].append(nf.get("title", k))
            continue

        # Refresh the observed facts, keep the human follow-up.
        keep = {kk: of.get(kk) for kk in ("status", "notes", "order") if kk in of}
        out = {**of, **nf, **keep}

        if of.get("status") == "fixed":
            out["status"] = "todo"
            out["severity"] = nf.get("severity", of.get("severity"))
            out["notes"] = (
                f"REGRESSION detectee le {today} : ce constat avait ete marque corrige, "
                f"il est reapparu au controle. Suivi precedent conserve ci-dessous. --- "
                + (of.get("notes") or "")
            )
            report["regressed"].append(of.get("title", k))
        elif of.get("status") == "accepted":
            report["kept"].append(of.get("title", k) + " (accepte)")
        else:
            report["kept"].append(of.get("title", k))
        merged.append(out)

    # Findings absent from the new pass: never auto-close them. Absence in one
    # run is not proof of a fix - a collector may simply have failed.
    for k, of in old_by_key.items():
        if k in new_by_key:
            continue
        if of.get("status") not in SETTLED:
            of["notes"] = (of.get("notes") or "") + (
                f" [Non observe lors du controle du {today} : a verifier a la main, "
                "l'absence dans une passe ne prouve pas la correction.]"
            )
            report["unseen"].append(of.get("title", k))
        merged.append(of)

    merged.sort(key=lambda f: (f.get("order", 999), str(f.get("id", ""))))
    for i, f in enumerate(merged, 1):
        f.setdefault("id", f"F{i}")

    out_doc = {**old, **{kk: vv for kk, vv in new.items() if kk != "findings"}}
    out_doc["findings"] = merged
    meta = out_doc.setdefault("meta", {})
    meta["date"] = new.get("meta", {}).get("date", meta.get("date", today))
    meta["last_pass"] = today
    # Merge the context lists without losing anything already written.
    for field in ("already_in_place", "accepted_risks", "not_covered"):
        seen, joined = set(), []
        for item in (old.get(field, []) + new.get(field, [])):
            if item not in seen:
                seen.add(item)
                joined.append(item)
        out_doc[field] = joined
    return out_doc, report


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    existing, incoming = Path(args[0]), Path(args[1])
    out = Path(args[2]) if len(args) > 2 else existing

    old = json.loads(existing.read_text(encoding="utf-8"))
    new = json.loads(incoming.read_text(encoding="utf-8"))
    today = date.today().isoformat()

    merged, rep = merge(old, new, today)
    if out == existing:
        shutil.copy(existing, existing.with_suffix(".json.bak"))
        print(f"backup: {existing.with_suffix('.json.bak')}")
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"merged: {out}  ({len(merged['findings'])} findings)")
    for label, items in (("REGRESSED", rep["regressed"]), ("new", rep["new"]),
                         ("not observed this pass", rep["unseen"]),
                         ("carried over", rep["kept"])):
        if items:
            print(f"\n{label} ({len(items)}):")
            for i in items:
                print(f"  - {i}")
    if rep["regressed"]:
        print("\nA regression outranks a new finding: something that was fixed came back.")
    print("\nNow re-render: render-report.py " + str(out))


if __name__ == "__main__":
    main()
