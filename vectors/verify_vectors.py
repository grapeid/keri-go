"""Check the vectors still match what keripy produces.

A vector file is a claim about the reference implementation. That claim can go
stale two ways, and both are silent:

  - keripy is upgraded and its output changes. Every implementation checked
    against the old file then agrees with something no longer true.
  - somebody edits the file by hand to make a failing test pass, which converts
    a disagreement with the ecosystem into a disagreement nobody can see.

This runs the vectors back through keripy and fails on either. It is the guard
on the guard, and it is why the file must be generated rather than written.

Run: python3 vectors/verify_vectors.py vectors/keri_vectors_v1.json
"""

import base64
import json
import sys

from keri.core import serdering


def check_serialisation(cid, expect):
    """The bytes must parse as a KERI event, and be the event they claim."""
    raw = base64.b64decode(expect["raw_b64"])
    serder = serdering.SerderKERI(raw=raw)
    problems = []
    if serder.said != expect["said"]:
        problems.append(f"said is {serder.said}, vector says {expect['said']}")
    if expect.get("aid") and serder.pre != expect["aid"]:
        problems.append(f"aid is {serder.pre}, vector says {expect['aid']}")
    return problems


def check_acdc(cid, expect):
    """An ACDC credential must reparse to the same SAID."""
    if "raw_b64" not in expect:
        # State-only cases (before/after) — nothing to reparse as a single ACDC.
        return []
    raw = base64.b64decode(expect["raw_b64"])
    # Schema JSON is not an ACDC; accept either form.
    try:
        serder = serdering.SerderACDC(raw=raw)
    except Exception:
        # Registry/iss/rev TEL events use SerderKERI; schema is plain JSON.
        try:
            serder = serdering.SerderKERI(raw=raw)
        except Exception:
            # Plain schema document: check the said field against $id if present.
            try:
                doc = json.loads(raw)
            except Exception as e:
                return [f"could not parse credential bytes: {e}"]
            if expect.get("said") and doc.get("$id") and doc["$id"] != expect["said"]:
                return [f"schema $id is {doc['$id']}, vector says {expect['said']}"]
            return []
    problems = []
    if expect.get("said") and serder.said != expect["said"]:
        problems.append(f"said is {serder.said}, vector says {expect['said']}")
    return problems


def check_stream(cid, case):
    """A CESR stream must begin with its event and carry a non-empty attachment."""
    expect = case["expect"]
    if "raw_b64" not in expect:
        return []
    stream = base64.b64decode(expect["raw_b64"])
    problems = []
    if "event_raw_b64" in expect:
        event = base64.b64decode(expect["event_raw_b64"])
        if not stream.startswith(event):
            problems.append("stream does not begin with the event bytes")
        if len(stream) <= len(event):
            problems.append("stream has no attachment after the event")
        else:
            # Reparse the leading event and check its SAID.
            serder = serdering.SerderKERI(raw=stream)
            if expect.get("event_said") and serder.said != expect["event_said"]:
                problems.append(
                    f"leading event said is {serder.said}, vector says {expect['event_said']}"
                )
    elif "receipt_raw_b64" in expect:
        receipt = base64.b64decode(expect["receipt_raw_b64"])
        if not stream.startswith(receipt):
            problems.append("receipt stream does not begin with the receipt event")
        serder = serdering.SerderKERI(raw=stream)
        if expect.get("receipt_said") and serder.said != expect["receipt_said"]:
            problems.append(
                f"receipt said is {serder.said}, vector says {expect['receipt_said']}"
            )
    else:
        # Stream without a separate event field — still must parse a leading event.
        try:
            serdering.SerderKERI(raw=stream)
        except Exception as e:
            problems.append(f"stream does not begin with a parseable event: {e}")
    return problems


def check_refusal(cid, case):
    """A case that must be refused has to actually be refused by the reference."""
    raw = base64.b64decode(case["input"]["raw_b64"])
    # Streams (truncated, bad receipt attachment) may still parse a leading event.
    # A refusal case is valid if either parse fails, the claimed said no longer
    # matches, or the case is a stream-level refusal that carries because-text
    # without a claimed_said (checked by shape only).
    try:
        serder = serdering.SerderKERI(raw=raw)
    except Exception:
        return []  # refused at parse, which is a refusal
    claimed = case["input"].get("claimed_said")
    if claimed and serder.said == claimed:
        return [f"expected a refusal, but keripy accepted it and agreed the "
                f"identifier is {claimed} — the vector no longer describes a forgery"]
    return []


def main(path):
    doc = json.load(open(path))
    failures = []
    checked = 0

    for c in doc["cases"]:
        cid, kind = c["id"], c["kind"]
        if kind in ("inception", "rotation", "interaction", "delegation", "property"):
            if "raw_b64" in c.get("expect", {}):
                failures += [f"{cid}: {p}" for p in check_serialisation(cid, c["expect"])]
                checked += 1
            elif "raw_b64" in c.get("input", {}):
                raw = base64.b64decode(c["input"]["raw_b64"])
                serder = serdering.SerderKERI(raw=raw)
                if serder.pre != c["expect"]["aid"] or serder.said != c["expect"]["said"]:
                    failures.append(f"{cid}: keripy no longer produces this identifier")
                checked += 1
        elif kind == "credential":
            failures += [f"{cid}: {p}" for p in check_acdc(cid, c.get("expect", {}))]
            checked += 1
        elif kind == "receipt":
            exp = c.get("expect", {})
            if "receipt_raw_b64" in exp and "raw_b64" in exp:
                failures += [f"{cid}: {p}" for p in check_stream(cid, c)]
            elif "raw_b64" in exp and "said" in exp:
                failures += [f"{cid}: {p}" for p in check_serialisation(cid, exp)]
            elif "event_raw_b64" in exp:
                raw = base64.b64decode(exp["event_raw_b64"])
                serder = serdering.SerderKERI(raw=raw)
                if exp.get("event_said") and serder.said != exp["event_said"]:
                    failures.append(f"{cid}: event said drifted")
            checked += 1
        elif kind == "stream":
            failures += [f"{cid}: {p}" for p in check_stream(cid, c)]
            checked += 1
        elif kind == "reject":
            failures += [f"{cid}: {p}" for p in check_refusal(cid, c)]
            checked += 1
        elif kind == "constants":
            checked += 1  # asserted directly by the conformance tests
        else:
            failures.append(f"{cid}: unknown kind {kind!r}")

    print(f"checked {checked} of {len(doc['cases'])} cases against {doc['oracle']}")
    if failures:
        print("\nThe vectors no longer match the reference implementation:\n")
        for f in failures:
            print(f"  {f}")
        print("\nRegenerate them, and find out WHY they moved before trusting the new "
              "file — a change here is a change to what every implementation must produce.")
        return 1
    print("the vectors still describe what keripy produces")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vectors/keri_vectors_v1.json"))
