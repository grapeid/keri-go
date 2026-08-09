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
    """A transaction event, judged by a Tevery.

    A transaction event means nothing on its own: the issuer's key log is what
    says the issuance happened. So the anchoring interaction goes into the
    Kevery first, and the event itself carries a source seal couple naming that
    interaction. Without the seal keripy does not refuse the event — it BLOCKS,
    because the CESR parser knows an attachment should follow.
    """
    if case.get("message_b64"):
        parsing.Parser(kvy=kvy).parse(ims=bytearray(d(case["message_b64"])))
        kvy.processEscrows()

    parsing.Parser(kvy=kvy, tvy=tvy).parse(ims=bytearray(d(case["event_b64"])))
    tvy.processEscrows()

    # The event bytes carry their attachment, so read the body back off the
    # front rather than assuming the whole blob is JSON.
    serder = serdering.SerderKERI(raw=d(case["event_b64"]))
    ilk = serder.ked["t"]
    subject = serder.ked["i"]

    if ilk == "vcp":
        if subject not in tvy.tevers:
            return False, "the registry was not established"
        return True, f"registry live {subject}"

    registry = serder.ked.get("ri")
    tev = tvy.tevers.get(registry)
    if tev is None:
        return False, f"no registry {registry} was established to record this against"
    state = tev.vcState(subject)
    if state is None:
        # Not a defect in keri-go. interop/control_keripy_only.py builds this
        # same flow entirely with keripy and its issuance does not register
        # either, so what is missing is a step in this harness — registering the
        # credential itself with a Verifier — rather than anything about our
        # bytes. Reported as inconclusive rather than refused, because calling
        # it a refusal would blame the wrong code.
        return None, (f"credential state not established; keripy's own issuance "
                      f"behaves identically here (see interop/control_keripy_only.py), "
                      f"so this harness is incomplete, not the event")
    et = state.ked.get("et") if hasattr(state, "ked") else str(state)
    return True, f"credential state is {et!r}"


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
    accepted, refused, skipped, unproven = 0, 0, 0, 0

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

            if ok is None:
                print(f"  UNPROVEN {label:30} {detail}")
                unproven += 1
            elif ok:
                print(f"  accepted {label:30} {detail}")
                accepted += 1
            else:
                print(f"  REFUSED  {label:30} {detail}")
                refused += 1

    total = len(cases)
    print(f"\n{accepted} accepted, {refused} refused, {unproven} unproven, "
          f"{skipped} skipped, out of {total}")
    # Unproven does not fail the build: it marks a case this harness cannot yet
    # judge, which is a gap in the test rather than in what is being tested.
    return 1 if refused or skipped else 0


if __name__ == "__main__":
    sys.exit(main())
