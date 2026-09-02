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

    merged, report = [], {"kept": [], "new": [], "regressed": [], "unseen": [],
                      "renumbered": [], "reordered": False}

    for k, nf in new_by_key.items():
        of = old_by_key.get(k)
        if of is None:
            nf.setdefault("status", "todo")
            nf["_incumbent"] = False
            nf["notes"] = (nf.get("notes") or "") + f" [Nouveau constat, {today}.]"
            merged.append(nf)
            report["new"].append(nf.get("title", k))
            continue

        # Refresh the observed facts, keep the human follow-up.
        keep = {kk: of.get(kk) for kk in ("status", "notes", "order") if kk in of}
        out = {**of, **nf, **keep, "_incumbent": True}

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
        of["_incumbent"] = True
        merged.append(of)

    # At an equal rank the finding that was already in the report comes first:
    # a newcomer arriving with `order: 1` must not displace the plan's own
    # first item.
    merged.sort(key=lambda f: (f.get("order", 999),
                               0 if f.get("_incumbent") else 1,
                               str(f.get("id", ""))))

    # Two identifiers must be unique across the whole report, and neither is
    # safe to take from the incoming pass: a pass written on its own numbers
    # its findings from F1 and orders them from 1, so anything new arrives
    # holding an id and a rank that the existing report has already given to
    # something else. Left alone, that ships a report with two findings called
    # F2 and two rows both labelled #3 - which is exactly what happened on the
    # run that produced this code. A finding already in the report keeps what
    # it has; a colliding newcomer is reassigned.
    # Incumbents reserve their ids first, unconditionally: the owner refers to a
    # finding by its id, in notes, in a ticket, out loud. Only a newcomer is
    # ever renamed, and only when the id it brought is already spoken for.
    taken = {f["id"] for f in merged if f.get("_incumbent") and f.get("id")}
    for f in merged:
        if f.get("_incumbent") and f.get("id"):
            continue
        fid = f.get("id")
        if not fid or fid in taken:
            n = 1
            while f"F{n}" in taken:
                n += 1
            fid = f"F{n}"
            if f.get("id"):
                report["renumbered"].append(f"{f['id']} -> {fid}  {f.get('title','')}")
            f["id"] = fid
        taken.add(fid)

    # Ranks become unique and contiguous, keeping the sequence above. `order`
    # is a plan, so only a human decides where a new finding really belongs:
    # this guarantees the report is readable, not that the plan is right.
    reordered = any(f.get("order") != i for i, f in enumerate(merged, 1))
    for i, f in enumerate(merged, 1):
        f["order"] = i
    if reordered:
        report["reordered"] = True
    for f in merged:
        f.pop("_incumbent", None)

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
                         ("new finding renamed to free an id", rep["renumbered"]),
                         ("carried over", rep["kept"])):
        if items:
            print(f"\n{label} ({len(items)}):")
            for i in items:
                print(f"  - {i}")
    if rep["regressed"]:
        print("\nA regression outranks a new finding: something that was fixed came back.")
    if rep["reordered"]:
        print("\nRanks were made unique and contiguous. `order` is the action plan, not the\n"
              "severity ranking, so review where the new findings landed before acting on it.")
    print("\nNow re-render: render-report.py " + str(out))


if __name__ == "__main__":
    main()
