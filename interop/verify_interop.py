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
from keri.vdr import viring


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


def judge_tel(kvy, tvy, case):
    """A transaction event, checked as far as this package can currently be checked.

    This is deliberately WEAKER than acceptance, and says so. A TEL event travels
    with a source seal couple naming the event in the issuer's key log that
    anchors it, and keri-go does not build that attachment yet — so keripy's
    Tevery cannot be handed one of our transaction events at all. Feeding it a
    bare event does not fail, it BLOCKS: the CESR parser waits for the
    attachment it knows should follow.

    What is checked here is that keripy recomputes the same identifier from our
    bytes. Combined with the byte-for-byte comparison in credentials_tel_test.go,
    that establishes the event body is right. It does not establish that the
    reference would accept it in a stream, and nothing here should be read as
    claiming otherwise.
    """
    if case.get("message_b64"):
        parsing.Parser(kvy=kvy).parse(ims=bytearray(d(case["message_b64"])))
        kvy.processEscrows()
    raw = d(case["event_b64"])
    serder = serdering.SerderKERI(raw=raw)
    if serder.said != json.loads(raw)["d"]:
        return False, "keripy recomputes a different identifier from these bytes"
    return True, f"{serder.ked['t']} body verified (not stream-accepted — see docstring)"


def judge_credential(case):
    """A credential is a document: its identifier must be a digest of itself."""
    raw = d(case["event_b64"])
    sad = json.loads(raw)
    from keri.core import coring
    said = sad["d"]
    # Recompute with keripy's own saidify, which is the interoperable check.
    from keri.core.coring import Saider
    _, recomputed = Saider.saidify(sad=dict(sad))
    if recomputed["d"] != said:
        return False, (f"keripy recomputes this credential's identifier as "
                       f"{recomputed['d']}, the credential says {said}")
    return True, f"identifier verified {said}"


def main():
    cases = json.load(sys.stdin)
    accepted, refused, skipped = 0, 0, 0

    with basing.openDB(name="interop") as db, viring.openReger(name="interop") as reger:
        kvy = eventing.Kevery(db=db, lax=True, local=True)
        tvy = vdr_eventing.Tevery(reger=reger, db=db, lax=True, local=True)

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
                    ok, detail = judge_tel(kvy, tvy, case)
                elif kind == "credential":
                    ok, detail = judge_credential(case)
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
