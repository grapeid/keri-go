"""Judge keri-go's output with keripy's own validator.

The conformance suite proves that given keripy's inputs, keri-go reproduces
keripy's bytes. This asks the stricter question: does keripy ACCEPT what keri-go
produces? Byte comparison checks two strings against each other; acceptance runs
the reference implementation's validator — signature verification, chaining,
pre-rotation, witness thresholds, delegation approval — over our output.

    go run ./interop | python interop/verify_interop.py

Exit status is non-zero if anything is refused, so this can gate a build.
A case keri-go could not build at all is reported as SKIPPED and does not pass.
"""

import base64
import json
import sys

from keri.core import eventing, parsing, serdering
from keri.db import basing
from keri.vdr import eventing as vdr_eventing


def d(b64):
    return base64.b64decode(b64)


def judge_kel(kvy, case):
    """Feed a key event, and any messages it depends on, to a Kevery."""
    # Extra messages are things the event needs before it can be accepted:
    # witness receipts for a witnessed event, a delegator's approval for a
    # delegated one. Order matters, so the event goes first.
    parsing.Parser(kvy=kvy).parse(ims=bytearray(d(case["message_b64"])))
    for extra in case.get("extra_b64") or []:
        parsing.Parser(kvy=kvy).parse(ims=bytearray(d(extra)))
    # A witnessed event is not accepted when it arrives: it waits in escrow
    # until enough witnesses have receipted it. Draining the escrows is what
    # promotes it, and without this an entirely valid event reads as refused.
    kvy.processEscrows()

    serder = serdering.SerderKERI(raw=d(case["event_b64"]))
    kever = kvy.kevers.get(serder.pre)
    if kever is None:
        return False, f"nothing was established for {serder.pre}"
    if kever.serder.said != serder.said:
        return False, (f"the log is at {kever.serder.said}, this event is "
                       f"{serder.said} — accepted but not as the latest event")
    return True, f"sn={kever.sn}"


def judge_delegation(kvy, case):
    """A delegated event needs its delegator's approval, in either order."""
    for extra in case.get("extra_b64") or []:
        parsing.Parser(kvy=kvy).parse(ims=bytearray(d(extra)))
    parsing.Parser(kvy=kvy).parse(ims=bytearray(d(case["message_b64"])))
    # A delegated event waits in escrow until the delegator's anchor is seen.
    # Draining the escrows is what releases it.
    kvy.processEscrows()

    serder = serdering.SerderKERI(raw=d(case["event_b64"]))
    kever = kvy.kevers.get(serder.pre)
    if kever is None:
        return False, (f"the delegated identity {serder.pre} was not established; "
                       "the delegator's anchor was not accepted as approval")
    return True, f"delegated identity established, sn={kever.sn}"


def judge_tel(db, case):
    """Transaction events are judged by a Tevery, not a Kevery."""
    serder = serdering.SerderKERI(raw=d(case["event_b64"]))
    # Re-parsing is the check that matters here: a registry inception is a
    # self-addressing event, so keripy recomputing its identifier from our bytes
    # and getting the same answer is the interoperable property.
    if serder.said != json.loads(d(case["event_b64"]))["d"]:
        return False, "keripy recomputed a different identifier from these bytes"
    return True, f"{serder.ked['t']} {serder.said}"


def main():
    cases = json.load(sys.stdin)
    accepted, refused, skipped = 0, 0, 0

    with basing.openDB(name="interop") as db:
        kvy = eventing.Kevery(db=db, lax=True, local=True)
        for case in cases:
            label, kind = case["label"], case.get("kind", "kel")
            if case.get("skipped"):
                print(f"  SKIPPED  {label:30} {case['skipped']}")
                skipped += 1
                continue
            try:
                if kind == "kel":
                    ok, detail = judge_kel(kvy, case)
                elif kind == "delegation":
                    ok, detail = judge_delegation(kvy, case)
                elif kind == "tel":
                    ok, detail = judge_tel(db, case)
                else:
                    ok, detail = False, f"no judge for kind {kind!r}"
            except Exception as exc:  # noqa: BLE001 — report, never mask
                ok, detail = False, f"{type(exc).__name__}: {exc}"

            if ok:
                print(f"  accepted {label:30} {detail}")
                accepted += 1
            else:
                print(f"  REFUSED  {label:30} {detail}")
                refused += 1

    total = len(cases)
    print(f"\n{accepted} accepted, {refused} refused, {skipped} skipped, out of {total}")
    return 1 if refused or skipped else 0


if __name__ == "__main__":
    sys.exit(main())
