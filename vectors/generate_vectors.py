"""Generate KERI conformance vectors from keripy.

WHAT THIS IS FOR

KERI identifiers are derived from the bytes of an event. Change one byte and you
have a different identity. So two implementations only interoperate if they
produce byte-for-byte identical output, and the only way to know that is to fix
the answers in advance and check every implementation against them.

keripy is the reference: Apache-2.0, and the implementations table lists it at
100% spec compliance for KERI, ACDC and CESR. So it is the oracle here. These
vectors are what IT produces, captured exactly, so that any other
implementation — our Go core, a Rust one, anything later — can be held to the
same answers.

WHY GENERATED RATHER THAN WRITTEN

A hand-written expectation is somebody's belief about what the answer should be.
A generated one is what the reference implementation actually does. Only the
second is worth checking against, and only the second can be regenerated when
the reference moves, which is how we would find out that it moved.

Run:  python3 tests/vectors/generate_vectors.py > tests/vectors/keri_vectors_v1.json
"""

import base64
import json
import sys

from keri.core import coring, eventing
from keri.core.coring import CtrDex, MtrDex
from keri.vc import proving
from keri.vdr import eventing as vdr_eventing

VECTOR_VERSION = 1

# Fixed wall-clock values so credential and TEL vectors regenerate identically.
FIXED_DT_ISSUE = "2024-01-01T00:00:00.000000+00:00"
FIXED_DT_REVOKE = "2024-06-01T00:00:00.000000+00:00"
# Fixed salts/nonces — random ones would make every run a different file.
FIXED_REGISTRY_NONCE = coring.Salter(raw=b"v" * 16).qb64
FIXED_PRIVACY_SALT = coring.Salter(raw=b"s" * 16).qb64


def signer(tag: str, transferable: bool = True) -> coring.Signer:
    """A deterministic key, so the vectors are reproducible.

    Fixed seeds rather than random ones: a vector whose inputs change on every
    run cannot be a fixed expectation.
    """
    raw = ((tag * 32)[:32]).encode()
    return coring.Signer(raw=raw, code=MtrDex.Ed25519_Seed, transferable=transferable)


def digest_of(verkey_qb64: str) -> str:
    """The pre-rotation commitment: a digest of the NEXT key, never the key."""
    return coring.Diger(ser=verkey_qb64.encode()).qb64


def dig(s: coring.Signer) -> str:
    return digest_of(s.verfer.qb64)


def case(cid, kind, why, inputs, serder):
    """One expectation: given these inputs, exactly these bytes and this identifier."""
    return {
        "id": cid,
        "kind": kind,
        "why": why,
        "input": inputs,
        "expect": {
            # The canonical serialisation, which is what a signature covers and
            # what the identifier is a digest of. Base64 so it survives JSON
            # without any encoder touching it.
            "raw_b64": base64.b64encode(serder.raw).decode(),
            "said": serder.said,
            "aid": serder.pre,
            # Carried for readability only. The bytes above are authoritative:
            # this field has been through a JSON encoder and its key order is
            # not the order that was signed.
            "event_readable": serder.ked,
        },
    }


def reject_case(cid, why, raw: bytes, *, claimed_said=None, because: str,
                extra_input=None):
    """A case the implementation must refuse.

    Expectations for refusals are still produced from keripy material: either a
    valid event whose bytes we then alter (so the digest no longer matches), or
    a well-formed event that is wrong relative to a prior event the input also
    carries. Never invent a said or raw_b64 from thin air.
    """
    inp = {
        "raw_b64": base64.b64encode(raw).decode(),
        "because": because,
    }
    if claimed_said is not None:
        inp["claimed_said"] = claimed_said
    if extra_input:
        inp.update(extra_input)
    return {
        "id": cid,
        "kind": "reject",
        "why": why,
        "input": inp,
        "expect": {"refused": True, "because": because},
    }


# ---------------------------------------------------------------------------
# Inception
# ---------------------------------------------------------------------------

def inception_cases():
    out = []

    # --- single-key (basic derivation: identifier is the key, D…) ---
    cur, nxt = signer("a"), signer("b")
    srdr = eventing.incept(keys=[cur.verfer.qb64], ndigs=[dig(nxt)])
    out.append(case(
        "icp/single-key/no-witnesses",
        "inception",
        "The simplest identity there is. If this one disagrees, nothing else can agree. "
        "Single-key inception uses basic derivation: the identifier is the key itself (D…), "
        "not a digest — an implementation that always digests produces identities nobody "
        "recognises.",
        {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)],
         "derivation": "basic"},
        srdr,
    ))

    # --- multi-key counts and integer thresholds (self-addressing: E…) ---
    for n_keys, isith in ((1, "1"), (2, "1"), (3, "2"), (5, "3")):
        if n_keys == 1:
            continue  # already covered above with basic derivation
        keys = [signer(f"k{n_keys}-{i}") for i in range(n_keys)]
        nexts = [signer(f"n{n_keys}-{i}") for i in range(n_keys)]
        srdr = eventing.incept(
            keys=[k.verfer.qb64 for k in keys],
            ndigs=[dig(n) for n in nexts],
            isith=isith, nsith=isith,
        )
        out.append(case(
            f"icp/{n_keys}-keys/{isith}-of-{n_keys}",
            "inception",
            "Multi-key inception uses self-addressing derivation: the identifier is a "
            "digest of the event (E…), equal to the SAID. An implementation that uses "
            "basic derivation here, or that formats the threshold as a number rather "
            f"than the string '{isith}', produces an identity no peer will recognise.",
            {"keys": [k.verfer.qb64 for k in keys],
             "next_digests": [dig(n) for n in nexts],
             "isith": isith, "nsith": isith,
             "derivation": "self-addressing"},
            srdr,
        ))

    # Fractional-weight thresholds (keripy accepts a list of fractions)
    k1, k2, k3 = signer("fw0"), signer("fw1"), signer("fw2")
    n1, n2, n3 = signer("fw3"), signer("fw4"), signer("fw5")
    isith_frac = ["1/2", "1/2", "1/2"]
    srdr = eventing.incept(
        keys=[k1.verfer.qb64, k2.verfer.qb64, k3.verfer.qb64],
        ndigs=[dig(n1), dig(n2), dig(n3)],
        isith=isith_frac, nsith=isith_frac,
    )
    out.append(case(
        "icp/three-keys/fractional-1-over-2-each",
        "inception",
        "Fractional thresholds are serialised as a list of strings, not a single "
        "integer. An implementation that only knows integer thresholds will either "
        "refuse a valid event or produce a different identity.",
        {"keys": [k1.verfer.qb64, k2.verfer.qb64, k3.verfer.qb64],
         "next_digests": [dig(n1), dig(n2), dig(n3)],
         "isith": isith_frac, "nsith": isith_frac,
         "derivation": "self-addressing"},
        srdr,
    ))

    # --- witnesses and toad ---
    cur, nxt = signer("a"), signer("b")
    # 1 witness, toad 1
    wits1 = [signer("w0", transferable=False).verfer.qb64]
    srdr = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)], wits=wits1, toad=1,
    )
    out.append(case(
        "icp/one-witness/toad-1",
        "inception",
        "A single witness is part of the identifier. An implementation that omits "
        "witnesses, or that uses transferable keys as witnesses, disagrees with every peer.",
        {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)],
         "witnesses": wits1, "toad": 1},
        srdr,
    ))

    # 3 witnesses, each valid toad
    wits3 = [signer(t, transferable=False).verfer.qb64 for t in ("w", "x", "y")]
    for toad in (1, 2, 3):
        srdr = eventing.incept(
            keys=[cur.verfer.qb64], ndigs=[dig(nxt)], wits=wits3, toad=toad,
        )
        out.append(case(
            f"icp/three-witnesses/toad-{toad}",
            "inception",
            "Witnesses and the threshold of acceptable duplicity (toad) are part of the "
            "identifier. Different toad values are different identities even with the "
            "same witness list.",
            {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)],
             "witnesses": wits3, "toad": toad},
            srdr,
        ))

    # 5 witnesses, a few toads
    wits5 = [signer(f"W{i}", transferable=False).verfer.qb64 for i in range(5)]
    for toad in (3, 5):
        srdr = eventing.incept(
            keys=[cur.verfer.qb64], ndigs=[dig(nxt)], wits=wits5, toad=toad,
        )
        out.append(case(
            f"icp/five-witnesses/toad-{toad}",
            "inception",
            "Larger witness sets still enter the digest. An implementation that truncates "
            "the list or reorders it produces a different identity.",
            {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)],
             "witnesses": wits5, "toad": toad},
            srdr,
        ))

    # --- anchored seals ---
    seal_one = [{"i": "EOwner0000000000000000000000000000000000000x", "r": "owner"}]
    srdr = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)], data=seal_one,
    )
    out.append(case(
        "icp/with-anchor-seal",
        "inception",
        "An anchored seal changes the identifier, which is the whole point of anchoring. "
        "An implementation that drops or reorders seals produces a different identity.",
        {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)], "data": seal_one},
        srdr,
    ))

    seal_several = [
        {"i": "EOwner0000000000000000000000000000000000000x", "r": "owner"},
        {"i": "EOther000000000000000000000000000000000000x", "s": "0",
         "d": "EDigest000000000000000000000000000000000000x"},
    ]
    srdr = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)], data=seal_several,
    )
    out.append(case(
        "icp/with-several-seals",
        "inception",
        "Several seals are ordered: swapping them changes the identifier. An "
        "implementation that sorts seals, or collapses them, is not interoperable.",
        {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)], "data": seal_several},
        srdr,
    ))

    # Field order inside a seal is part of the event bytes.
    # Insertion order is preserved by Python 3.7+ dicts and by keripy's serialiser.
    seal_usual = [{"i": "ECredential000000000000000000000000000000x",
                   "s": "0",
                   "d": "EDigest000000000000000000000000000000000000x"}]
    seal_unusual = [{"d": "EDigest000000000000000000000000000000000000x",
                     "i": "ECredential000000000000000000000000000000x",
                     "s": "0"}]
    srdr_usual = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)], data=seal_usual,
    )
    srdr_unusual = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)], data=seal_unusual,
    )
    assert srdr_usual.said != srdr_unusual.said, (
        "seal field order did not change the identifier — the trap this case "
        "exists to catch is not present in this keripy version"
    )
    out.append(case(
        "icp/seal-field-order/i-s-d",
        "inception",
        "Seal field order is part of the signed bytes. Alphabetical sorting of seal "
        "keys produces a different identifier than the order the event was written in.",
        {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)], "data": seal_usual},
        srdr_usual,
    ))
    out.append(case(
        "icp/seal-field-order/d-i-s",
        "inception",
        "A seal written d-then-i-then-s is a different event from one written i-s-d. "
        "An implementation that puts seals through a hash map silently changes every "
        "anchored identity.",
        {"keys": [cur.verfer.qb64], "next_digests": [dig(nxt)], "data": seal_unusual},
        srdr_unusual,
    ))

    return out


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

def rotation_cases():
    out = []

    # Simple single-key rotation
    cur, nxt, nxt2 = signer("a"), signer("b"), signer("c")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[dig(nxt)])
    rot = eventing.rotate(
        pre=icp.pre, keys=[nxt.verfer.qb64], dig=icp.said, sn=1,
        ndigs=[dig(nxt2)],
    )
    out.append(case(
        "rot/simple/sn-1",
        "rotation",
        "A rotation must carry the key the previous event committed to, and must chain "
        "to that event by digest. Both are places an implementation can quietly differ.",
        {"prefix": icp.pre, "keys": [nxt.verfer.qb64], "prior_said": icp.said,
         "sn": 1, "next_digests": [dig(nxt2)],
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        rot,
    ))

    # Threshold change on multi-key
    k1, k2, k3 = signer("m"), signer("n"), signer("o")
    n1, n2, n3 = signer("p"), signer("q"), signer("r")
    n4, n5, n6 = signer("s"), signer("t"), signer("u")
    icp = eventing.incept(
        keys=[k1.verfer.qb64, k2.verfer.qb64, k3.verfer.qb64],
        ndigs=[dig(n1), dig(n2), dig(n3)],
        isith="2", nsith="2",
    )
    rot = eventing.rotate(
        pre=icp.pre,
        keys=[n1.verfer.qb64, n2.verfer.qb64, n3.verfer.qb64],
        dig=icp.said, sn=1,
        ndigs=[dig(n4), dig(n5), dig(n6)],
        isith="3", nsith="2",
    )
    out.append(case(
        "rot/threshold-change/2-of-3-to-3-of-3",
        "rotation",
        "Changing the threshold is itself a commitment recorded in the event. An "
        "implementation that leaves the old threshold in place, or encodes the new "
        "one as a number rather than a string, disagrees with every peer about who "
        "may sign next.",
        {"prefix": icp.pre,
         "keys": [n1.verfer.qb64, n2.verfer.qb64, n3.verfer.qb64],
         "prior_said": icp.said, "sn": 1,
         "next_digests": [dig(n4), dig(n5), dig(n6)],
         "isith": "3", "nsith": "2",
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        rot,
    ))

    # Witness adds, cuts, and both
    cur, nxt, nxt2 = signer("a"), signer("b"), signer("c")
    w1 = signer("w", transferable=False)
    w2 = signer("x", transferable=False)
    w3 = signer("y", transferable=False)
    wits = [w1.verfer.qb64, w2.verfer.qb64]
    icp = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)], wits=wits, toad=1,
    )

    rot_add = eventing.rotate(
        pre=icp.pre, keys=[nxt.verfer.qb64], dig=icp.said, sn=1,
        ndigs=[dig(nxt2)], wits=wits, adds=[w3.verfer.qb64], toad=2,
    )
    out.append(case(
        "rot/witness-adds/one",
        "rotation",
        "Adding a witness is recorded as ba (backers add). An implementation that "
        "rewrites the full witness list instead of emitting the delta, or that "
        "omits the new toad, produces a rotation no peer will accept.",
        {"prefix": icp.pre, "keys": [nxt.verfer.qb64], "prior_said": icp.said,
         "sn": 1, "next_digests": [dig(nxt2)],
         "prior_witnesses": wits, "adds": [w3.verfer.qb64], "toad": 2,
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        rot_add,
    ))

    rot_cut = eventing.rotate(
        pre=icp.pre, keys=[nxt.verfer.qb64], dig=icp.said, sn=1,
        ndigs=[dig(nxt2)], wits=wits, cuts=[w2.verfer.qb64], toad=1,
    )
    out.append(case(
        "rot/witness-cuts/one",
        "rotation",
        "Removing a witness is recorded as br (backers remove). An implementation "
        "that drops a witness without emitting br has not said what it thinks it said.",
        {"prefix": icp.pre, "keys": [nxt.verfer.qb64], "prior_said": icp.said,
         "sn": 1, "next_digests": [dig(nxt2)],
         "prior_witnesses": wits, "cuts": [w2.verfer.qb64], "toad": 1,
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        rot_cut,
    ))

    rot_both = eventing.rotate(
        pre=icp.pre, keys=[nxt.verfer.qb64], dig=icp.said, sn=1,
        ndigs=[dig(nxt2)], wits=wits,
        cuts=[w1.verfer.qb64], adds=[w3.verfer.qb64], toad=1,
    )
    out.append(case(
        "rot/witness-cuts-and-adds/one-each",
        "rotation",
        "Cuts and adds in the same rotation are ordered fields of one event. "
        "Swapping them, or applying them in the wrong order to reconstruct the "
        "witness set, yields a different next state.",
        {"prefix": icp.pre, "keys": [nxt.verfer.qb64], "prior_said": icp.said,
         "sn": 1, "next_digests": [dig(nxt2)],
         "prior_witnesses": wits,
         "cuts": [w1.verfer.qb64], "adds": [w3.verfer.qb64], "toad": 1,
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        rot_both,
    ))

    # Rotation carrying a seal
    seal = [{"i": "EOwner0000000000000000000000000000000000000x", "r": "owner"}]
    cur, nxt, nxt2 = signer("ra"), signer("rb"), signer("rc")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[dig(nxt)])
    rot = eventing.rotate(
        pre=icp.pre, keys=[nxt.verfer.qb64], dig=icp.said, sn=1,
        ndigs=[dig(nxt2)], data=seal,
    )
    out.append(case(
        "rot/with-anchor-seal",
        "rotation",
        "A rotation can anchor data the same way an interaction can. Dropping the "
        "seal, or serialising it differently, changes the event digest and breaks "
        "the chain for anyone verifying against the real history.",
        {"prefix": icp.pre, "keys": [nxt.verfer.qb64], "prior_said": icp.said,
         "sn": 1, "next_digests": [dig(nxt2)], "data": seal,
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        rot,
    ))

    # Chain of three rotations (four establishment events total including icp)
    keys = [signer(f"ch{i}") for i in range(6)]
    icp = eventing.incept(keys=[keys[0].verfer.qb64], ndigs=[dig(keys[1])])
    chain = [icp]
    for sn in (1, 2, 3):
        rot = eventing.rotate(
            pre=icp.pre,
            keys=[keys[sn].verfer.qb64],
            dig=chain[-1].said,
            sn=sn,
            ndigs=[dig(keys[sn + 1])],
        )
        out.append(case(
            f"rot/chain/sn-{sn}",
            "rotation",
            "Each rotation digests the previous event. An implementation that always "
            "points at the inception, or that mis-encodes the sequence number as it "
            f"grows past single digits (sn={sn}), cannot be followed by anyone else.",
            {"prefix": icp.pre,
             "keys": [keys[sn].verfer.qb64],
             "prior_said": chain[-1].said,
             "sn": sn,
             "next_digests": [dig(keys[sn + 1])],
             "prior_event_raw_b64": base64.b64encode(chain[-1].raw).decode(),
             "inception_raw_b64": base64.b64encode(icp.raw).decode()},
            rot,
        ))
        chain.append(rot)

    return out


# ---------------------------------------------------------------------------
# Interaction
# ---------------------------------------------------------------------------

def interaction_cases():
    out = []
    cur, nxt = signer("a"), signer("b")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[dig(nxt)])

    # No seals
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=[])
    out.append(case(
        "ixn/no-seals",
        "interaction",
        "An interaction with an empty seal list is still a real event with a real "
        "digest. An implementation that omits the 'a' field entirely, rather than "
        "emitting an empty array, produces bytes no peer will verify.",
        {"prefix": icp.pre, "prior_said": icp.said, "sn": 1, "data": [],
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        ixn,
    ))

    # One seal
    seal = [{"i": "ECredential000000000000000000000000000000x", "s": "0",
             "d": "EDigest000000000000000000000000000000000000x"}]
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=seal)
    out.append(case(
        "ixn/one-seal",
        "interaction",
        "Interaction events are how a credential is anchored into a key history, so "
        "their serialisation decides whether an issuance can be verified elsewhere.",
        {"prefix": icp.pre, "prior_said": icp.said, "sn": 1, "data": seal,
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        ixn,
    ))

    # Several seals
    seals = [
        {"i": "ECredential000000000000000000000000000000x", "s": "0",
         "d": "EDigest000000000000000000000000000000000000x"},
        {"i": "EOtherCred0000000000000000000000000000000x", "s": "0",
         "d": "EOtherDig000000000000000000000000000000000x"},
    ]
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=seals)
    out.append(case(
        "ixn/several-seals",
        "interaction",
        "Multiple seals are ordered. Sorting them, or hashing them as a set, changes "
        "the event digest and makes the anchor unverifiable.",
        {"prefix": icp.pre, "prior_said": icp.said, "sn": 1, "data": seals,
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        ixn,
    ))

    # Seal field order trap on interaction
    seal_dis = [{"d": "EDigest000000000000000000000000000000000000x",
                 "i": "ECredential000000000000000000000000000000x",
                 "s": "0"}]
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=seal_dis)
    out.append(case(
        "ixn/seal-field-order/d-i-s",
        "interaction",
        "Seal field order is part of the signed bytes on interaction events too. "
        "A hash-map serialiser turns a valid anchor into a different event.",
        {"prefix": icp.pre, "prior_said": icp.said, "sn": 1, "data": seal_dis,
         "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
        ixn,
    ))

    # Large sequence numbers — hex formatting past 9 and past 15
    for sn in (10, 16, 255, 256):
        ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=sn, data=seal)
        out.append(case(
            f"ixn/sequence-number/{sn}",
            "interaction",
            f"Sequence numbers are lowercase hex strings without a 0x prefix. sn={sn} "
            f"serialises as '{ixn.ked['s']}'. An implementation that uses decimal, "
            "uppercase, or padded hex produces an event nobody else can chain from.",
            {"prefix": icp.pre, "prior_said": icp.said, "sn": sn, "data": seal,
             "prior_event_raw_b64": base64.b64encode(icp.raw).decode()},
            ixn,
        ))

    return out


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------

def delegation_cases():
    out = []

    # Delegator inception (ordinary), then delegated inception (dip)
    d_cur, d_nxt = signer("D0"), signer("D1")
    delegator = eventing.incept(keys=[d_cur.verfer.qb64], ndigs=[dig(d_nxt)])
    out.append(case(
        "del/delegator-inception",
        "inception",
        "The delegator is an ordinary identifier. Recorded so a chain that includes "
        "a delegated identifier has the root event the rest of the chain points at.",
        {"keys": [d_cur.verfer.qb64], "next_digests": [dig(d_nxt)]},
        delegator,
    ))

    c_cur, c_nxt = signer("C0"), signer("C1")
    dip = eventing.delcept(
        keys=[c_cur.verfer.qb64], ndigs=[dig(c_nxt)], delpre=delegator.pre,
    )
    out.append(case(
        "del/delegated-inception/dip",
        "delegation",
        "A delegated inception (dip) names its delegator in di and uses self-addressing "
        "derivation. An implementation that emits an ordinary icp, or that omits di, "
        "has not created a delegated identifier.",
        {"keys": [c_cur.verfer.qb64], "next_digests": [dig(c_nxt)],
         "delegator": delegator.pre,
         "delegator_raw_b64": base64.b64encode(delegator.raw).decode()},
        dip,
    ))

    # Delegator anchors the dip
    seal = [{"i": dip.pre, "s": "0", "d": dip.said}]
    anchor = eventing.interact(
        pre=delegator.pre, dig=delegator.said, sn=1, data=seal,
    )
    out.append(case(
        "del/delegator-anchors-dip",
        "interaction",
        "Delegation is only complete when the delegator anchors the dip. The seal "
        "must carry the delegated identifier, its sequence number, and its SAID — "
        "any other shape is not a delegation anchor.",
        {"prefix": delegator.pre, "prior_said": delegator.said, "sn": 1,
         "data": seal,
         "delegated_aid": dip.pre, "delegated_said": dip.said,
         "prior_event_raw_b64": base64.b64encode(delegator.raw).decode(),
         "dip_raw_b64": base64.b64encode(dip.raw).decode()},
        anchor,
    ))

    # Delegated rotation (drt)
    c_nxt2 = signer("C2")
    drt = eventing.deltate(
        pre=dip.pre, keys=[c_nxt.verfer.qb64], dig=dip.said, sn=1,
        ndigs=[dig(c_nxt2)],
    )
    out.append(case(
        "del/delegated-rotation/drt",
        "delegation",
        "A delegated rotation (drt) is not an ordinary rot: the ilk differs, and "
        "acceptance still depends on the delegator's authority. Emitting rot here "
        "produces an event no peer treating this as delegated will accept.",
        {"prefix": dip.pre, "keys": [c_nxt.verfer.qb64], "prior_said": dip.said,
         "sn": 1, "next_digests": [dig(c_nxt2)],
         "prior_event_raw_b64": base64.b64encode(dip.raw).decode(),
         "delegator": delegator.pre},
        drt,
    ))

    return out


# ---------------------------------------------------------------------------
# Rejection cases
# ---------------------------------------------------------------------------

def rejection_cases():
    out = []
    cur, nxt, nxt2 = signer("a"), signer("b"), signer("c")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[dig(nxt)])

    # 1. Contents do not digest to the claimed identifier
    tampered = icp.raw.replace(b'"kt":"1"', b'"kt":"2"', 1)
    out.append(reject_case(
        "reject/said-does-not-match-contents",
        "An event whose contents do not digest to the identifier it claims must be "
        "refused. Accepting it would let a forged event borrow a real identity, which "
        "is what the digest exists to prevent.",
        tampered,
        claimed_said=icp.said,
        because="the contents do not digest to the claimed identifier",
    ))

    # 2. Rotation carrying a key the previous event did not commit to
    wrong_key = signer("ZZ")  # not the pre-rotated nxt
    bad_rot = eventing.rotate(
        pre=icp.pre, keys=[wrong_key.verfer.qb64], dig=icp.said, sn=1,
        ndigs=[dig(nxt2)],
    )
    out.append(reject_case(
        "reject/rotation-key-not-precommitted",
        "A rotation must present a key the previous establishment event committed to "
        "via its next-key digests. Accepting any other key lets an attacker take over "
        "the identifier without holding the committed material.",
        bad_rot.raw,
        because="the rotation key was not committed to by the prior event's next digests",
        extra_input={
            "prior_event_raw_b64": base64.b64encode(icp.raw).decode(),
            "prior_next_digests": [dig(nxt)],
            "presented_keys": [wrong_key.verfer.qb64],
        },
    ))

    # 3. Sequence number that skips
    skip = eventing.interact(pre=icp.pre, dig=icp.said, sn=2, data=[])
    out.append(reject_case(
        "reject/sequence-number-skips",
        "Sequence numbers must be contiguous. Accepting a skip lets an attacker "
        "insert a hidden event later, or drop one, without the gap being obvious.",
        skip.raw,
        because="sequence number 2 does not follow the prior event at sn 0",
        extra_input={
            "prior_event_raw_b64": base64.b64encode(icp.raw).decode(),
            "prior_sn": 0,
            "presented_sn": 2,
        },
    ))

    # 4. Prior-event digest that does not match
    other = eventing.incept(
        keys=[signer("other0").verfer.qb64],
        ndigs=[dig(signer("other1"))],
    )
    wrong_prior = eventing.interact(
        pre=icp.pre, dig=other.said, sn=1, data=[],
    )
    out.append(reject_case(
        "reject/prior-digest-mismatch",
        "Every non-inception event digests its predecessor. Accepting a wrong prior "
        "digest attaches the event to a history it does not belong to.",
        wrong_prior.raw,
        because="the prior-event digest does not match the SAID of the previous event",
        extra_input={
            "prior_event_raw_b64": base64.b64encode(icp.raw).decode(),
            "presented_prior_said": other.said,
            "actual_prior_said": icp.said,
        },
    ))

    # 5. Threshold larger than the number of keys — tamper kt on a valid event
    multi = eventing.incept(
        keys=[signer("t0").verfer.qb64, signer("t1").verfer.qb64],
        ndigs=[dig(signer("t2")), dig(signer("t3"))],
        isith="1", nsith="1",
    )
    # kt "1" → "3" with only 2 keys
    over = multi.raw.replace(b'"kt":"1"', b'"kt":"3"', 1)
    out.append(reject_case(
        "reject/threshold-exceeds-key-count",
        "A signing threshold larger than the number of keys can never be met. "
        "Accepting it creates an identifier that can never produce a valid signature "
        "set, which is not a usable identity.",
        over,
        claimed_said=multi.said,
        because="the signing threshold is larger than the number of keys supplied",
    ))

    # 6. Field the schema does not define — inject an unknown top-level field.
    # Rebuild via parse of valid event, then append a field into the raw JSON
    # carefully enough that the result is still parseable as JSON but is not a
    # schema-valid KERI event. We splice before the closing brace.
    assert multi.raw.endswith(b"}")
    with_extra = multi.raw[:-1] + b',"not_a_keri_field":"x"}'
    out.append(reject_case(
        "reject/undefined-field",
        "An event carrying a field the KERI schema does not define must be refused. "
        "Accepting unknown fields lets two implementations disagree about what was "
        "signed while appearing to share an identifier.",
        with_extra,
        claimed_said=multi.said,
        because="the event carries a field the schema does not define",
    ))

    # Keep the original id used by the first vector file for continuity.
    out.append(reject_case(
        "property/tampered-event-is-refused",
        "An event whose contents do not digest to the identifier it claims must be "
        "refused. Accepting it would let a forged event borrow a real identity, which "
        "is what the digest exists to prevent.",
        tampered,
        claimed_said=icp.said,
        because="the contents do not digest to the claimed identifier",
    ))

    return out


# ---------------------------------------------------------------------------
# Properties and constants
# ---------------------------------------------------------------------------

def identifier_property_cases():
    """Properties that hold for every conformant implementation, stated as data."""
    cur, nxt = signer("a"), signer("b")
    icp = eventing.incept(keys=[cur.verfer.qb64], ndigs=[dig(nxt)])

    # Multi-key: aid MUST equal said (self-addressing)
    k1, k2 = signer("prop0"), signer("prop1")
    n1, n2 = signer("prop2"), signer("prop3")
    multi = eventing.incept(
        keys=[k1.verfer.qb64, k2.verfer.qb64],
        ndigs=[dig(n1), dig(n2)],
        isith="1", nsith="1",
    )

    return [
        {
            "id": "property/single-key-aid-is-the-key",
            "kind": "property",
            "why": "Single-key inception uses basic derivation: the identifier is the "
                   "public key (D…), not the event digest. An implementation that always "
                   "sets aid = said breaks every single-key identity that already exists.",
            "assert": "aid_equals_key_not_said",
            "input": {"raw_b64": base64.b64encode(icp.raw).decode()},
            "expect": {"aid": icp.pre, "said": icp.said, "key": cur.verfer.qb64},
        },
        {
            "id": "property/multi-key-aid-is-said",
            "kind": "property",
            "why": "Multi-key inception uses self-addressing derivation: the identifier "
                   "IS the digest of the event. An implementation where these differ has "
                   "not made a multi-key identity.",
            "assert": "aid_equals_said",
            "input": {"raw_b64": base64.b64encode(multi.raw).decode()},
            "expect": {"aid": multi.pre, "said": multi.said},
        },
        {
            "id": "property/aid-is-said-of-inception",
            "kind": "property",
            "why": "Kept for continuity with the first vector file. For this multi-key "
                   "style event the aid equals the said; for single-key basic derivation "
                   "it does not — see property/single-key-aid-is-the-key.",
            "assert": "aid_equals_said",
            "input": {"raw_b64": base64.b64encode(multi.raw).decode()},
            "expect": {"aid": multi.pre, "said": multi.said},
        },
    ]


def cesr_code_cases():
    """The code table is normative in the spec: these characters are fixed."""
    return [{
        "id": "cesr/codes",
        "kind": "constants",
        "why": "CESR codes are normative. An implementation that emits a different "
               "prefix is producing values no other implementation can read.",
        "input": {},
        "expect": {
            "blake3_256": MtrDex.Blake3_256,
            "ed25519_pubkey": MtrDex.Ed25519,
            "ed25519_pubkey_nontransferable": MtrDex.Ed25519N,
            "ed25519_seed": MtrDex.Ed25519_Seed,
            "ed25519_sig": MtrDex.Ed25519_Sig,
            # Attachment group introducers — what arrives on the wire after an event.
            "controller_idx_sigs": CtrDex.ControllerIdxSigs,
            "witness_idx_sigs": CtrDex.WitnessIdxSigs,
            "nontrans_receipt_couples": CtrDex.NonTransReceiptCouples,
            "trans_receipt_quadruples": CtrDex.TransReceiptQuadruples,
            "attached_material_quadlets": CtrDex.AttachedMaterialQuadlets,
        },
    }]


# ---------------------------------------------------------------------------
# ACDC credentials, registries, issuance, revocation
# ---------------------------------------------------------------------------

def _saidified_schema():
    """A minimal JSON schema whose $id is its own SAID — fixed for the vectors."""
    schema = {
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "TestCredential",
        "description": "Schema used only by the conformance vectors",
        "type": "object",
        "properties": {
            "d": {"type": "string"},
            "i": {"type": "string"},
            "dt": {"type": "string"},
            "name": {"type": "string"},
            "score": {"type": "integer"},
        },
        "additionalProperties": True,
        "required": ["dt"],
    }
    _, saidified = coring.Saider.saidify(
        sad=schema, kind=coring.Serials.json, label="$id",
    )
    return saidified


def _credential_case(cid, why, creder, *, inputs, extra_expect=None):
    """One ACDC: the SAID is the value a verifier must reproduce offline."""
    sad = creder.sad if hasattr(creder, "sad") else creder.ked
    exp = {
        "raw_b64": base64.b64encode(creder.raw).decode(),
        "said": creder.said,
        "issuer": sad.get("i"),
        "schema_said": sad.get("s"),
        "registry": sad.get("ri"),
        "subject_said": (sad.get("a") or {}).get("d"),
        "credential_readable": sad,
    }
    if extra_expect:
        exp.update(extra_expect)
    return {
        "id": cid,
        "kind": "credential",
        "why": why,
        "input": inputs,
        "expect": exp,
    }


def credential_cases():
    out = []

    schema = _saidified_schema()
    schema_said = schema["$id"]
    schema_raw = json.dumps(schema, separators=(",", ":")).encode()

    # The schema itself is something a verifier holds; capture its SAID and bytes.
    out.append({
        "id": "acdc/schema/test-credential",
        "kind": "credential",
        "why": "A credential's schema SAID is part of what a verifier checks offline. "
               "An implementation that recomputes a different SAID for the same schema "
               "rejects every credential issued against it, or accepts forged ones.",
        "input": {"schema": schema},
        "expect": {
            "raw_b64": base64.b64encode(schema_raw).decode(),
            "said": schema_said,
            "schema_readable": schema,
        },
    })

    iss_cur, iss_nxt = signer("iss0"), signer("iss1")
    issuer_icp = eventing.incept(
        keys=[iss_cur.verfer.qb64], ndigs=[dig(iss_nxt)],
    )
    rec_cur, rec_nxt = signer("rec0"), signer("rec1")
    recipient_icp = eventing.incept(
        keys=[rec_cur.verfer.qb64], ndigs=[dig(rec_nxt)],
    )

    # Registry (TEL inception) — backerless, fixed nonce
    reg = vdr_eventing.incept(
        pre=issuer_icp.pre, toad=0, baks=[], nonce=FIXED_REGISTRY_NONCE,
    )
    out.append(case(
        "acdc/registry/vcp-backerless",
        "credential",
        "A credential registry is itself a self-addressing identifier. An "
        "implementation that formats the registry inception differently produces a "
        "registry no issued credential will name, so every issuance fails to bind.",
        {"issuer": issuer_icp.pre, "toad": 0, "backers": [],
         "nonce": FIXED_REGISTRY_NONCE,
         "issuer_inception_raw_b64": base64.b64encode(issuer_icp.raw).decode()},
        reg,
    ))

    claims = {"name": "Alice", "dt": FIXED_DT_ISSUE, "score": 42}

    # Credential issued INTO a registry
    creder_reg = proving.credential(
        schema=schema_said,
        issuer=issuer_icp.pre,
        data=dict(claims),
        recipient=recipient_icp.pre,
        status=reg.pre,
    )
    out.append(_credential_case(
        "acdc/issued-into-registry",
        "A registry-backed credential names its registry in ri, and its own SAID is "
        "a digest of its canonical bytes. A verifier offline must recompute that SAID "
        "exactly; any other serialisation means the credential cannot be checked.",
        creder_reg,
        inputs={
            "schema_said": schema_said,
            "issuer": issuer_icp.pre,
            "recipient": recipient_icp.pre,
            "registry": reg.pre,
            "data": claims,
        },
    ))

    # Credential issued WITHOUT a registry
    creder_bare = proving.credential(
        schema=schema_said,
        issuer=issuer_icp.pre,
        data=dict(claims),
        recipient=recipient_icp.pre,
        status=None,
    )
    out.append(_credential_case(
        "acdc/issued-without-registry",
        "Not every credential is registry-backed. Omitting ri is part of the "
        "serialisation: inventing a registry field, or requiring one, produces a "
        "different SAID and a credential no peer recognises.",
        creder_bare,
        inputs={
            "schema_said": schema_said,
            "issuer": issuer_icp.pre,
            "recipient": recipient_icp.pre,
            "registry": None,
            "data": claims,
        },
    ))

    # Issuance event (TEL iss) that places the credential in the registry
    iss = vdr_eventing.issue(
        vcdig=creder_reg.said, regk=reg.pre, dt=FIXED_DT_ISSUE,
    )
    out.append(case(
        "acdc/issuance-event/iss",
        "credential",
        "Issuance is a TEL event whose identifier is the credential's SAID. An "
        "implementation that digests the wrong fields, or that points ri at the "
        "issuer rather than the registry, cannot be reconciled with any peer's TEL.",
        {"credential_said": creder_reg.said, "registry": reg.pre,
         "dt": FIXED_DT_ISSUE,
         "credential_raw_b64": base64.b64encode(creder_reg.raw).decode(),
         "registry_raw_b64": base64.b64encode(reg.raw).decode()},
        iss,
    ))

    # Issuer anchors the iss into its KEL — the seal a verifier walks to
    anchor_seal = [{"i": reg.pre, "s": iss.ked["s"], "d": iss.said}]
    anchor = eventing.interact(
        pre=issuer_icp.pre, dig=issuer_icp.said, sn=1, data=anchor_seal,
    )
    out.append(case(
        "acdc/issuance-anchor/ixn",
        "interaction",
        "A registry issuance is only bound to the issuer when the issuer anchors it. "
        "The seal carries the registry, the TEL sequence number and the iss SAID — "
        "any other shape is not an issuance anchor and will not verify offline.",
        {"prefix": issuer_icp.pre, "prior_said": issuer_icp.said, "sn": 1,
         "data": anchor_seal,
         "credential_said": creder_reg.said, "iss_said": iss.said,
         "prior_event_raw_b64": base64.b64encode(issuer_icp.raw).decode()},
        anchor,
    ))

    # Edge (link to another credential)
    edge = {"n": creder_reg.said, "s": schema_said}
    creder_edge = proving.credential(
        schema=schema_said,
        issuer=issuer_icp.pre,
        data={"name": "Carol", "dt": FIXED_DT_ISSUE},
        recipient=recipient_icp.pre,
        status=reg.pre,
        source=edge,
    )
    out.append(_credential_case(
        "acdc/with-edge",
        "An edge chains one credential to another. The edge is inside the SAID, so "
        "dropping it, reordering it, or changing the nested schema reference produces "
        "a different credential that no longer proves the link.",
        creder_edge,
        inputs={
            "schema_said": schema_said,
            "issuer": issuer_icp.pre,
            "recipient": recipient_icp.pre,
            "registry": reg.pre,
            "data": {"name": "Carol", "dt": FIXED_DT_ISSUE},
            "source": edge,
        },
    ))

    # No edge (explicit contrast already covered by issued-into-registry)

    # Rules section
    rules = [{"l": "usageDisclaimer", "s": "use carefully"}]
    creder_rules = proving.credential(
        schema=schema_said,
        issuer=issuer_icp.pre,
        data={"name": "Dan", "dt": FIXED_DT_ISSUE},
        recipient=recipient_icp.pre,
        status=reg.pre,
        rules=rules,
    )
    out.append(_credential_case(
        "acdc/with-rules",
        "Rules travel inside the credential and enter its SAID. An implementation "
        "that strips the rules section, or that serialises it differently, produces "
        "a credential whose digest no longer matches what was issued.",
        creder_rules,
        inputs={
            "schema_said": schema_said,
            "issuer": issuer_icp.pre,
            "recipient": recipient_icp.pre,
            "registry": reg.pre,
            "data": {"name": "Dan", "dt": FIXED_DT_ISSUE},
            "rules": rules,
        },
    ))

    # Privacy-preserving ACDC (fixed salt) — the form selective disclosure builds on.
    # keripy 1.1.17 exposes the private/salt path; a full partial-disclosure
    # presentation API is not exercised here because it is not a pure function of
    # fixed inputs in this version.
    creder_private = proving.credential(
        schema=schema_said,
        issuer=issuer_icp.pre,
        data={"name": "Eve", "dt": FIXED_DT_ISSUE, "score": 7},
        recipient=recipient_icp.pre,
        status=reg.pre,
        private=True,
        salt=FIXED_PRIVACY_SALT,
    )
    out.append(_credential_case(
        "acdc/private-with-salt",
        "A privacy-preserving credential carries a salt (u) at the top level and in "
        "the subject. That salt is part of the SAID. An implementation that omits it, "
        "or that generates a fresh one on read, cannot verify a credential it did not "
        "itself issue — and selective disclosure depends on this form.",
        creder_private,
        inputs={
            "schema_said": schema_said,
            "issuer": issuer_icp.pre,
            "recipient": recipient_icp.pre,
            "registry": reg.pre,
            "data": {"name": "Eve", "dt": FIXED_DT_ISSUE, "score": 7},
            "private": True,
            "salt": FIXED_PRIVACY_SALT,
        },
        extra_expect={"salt": FIXED_PRIVACY_SALT},
    ))

    # Revocation: state before (iss) already captured; rev event; after
    rev = vdr_eventing.revoke(
        vcdig=creder_reg.said, regk=reg.pre, dig=iss.said, dt=FIXED_DT_REVOKE,
    )
    out.append(case(
        "acdc/revocation-event/rev",
        "credential",
        "Revocation is a TEL event that chains to the issuance by digest. An "
        "implementation that does not require that link, or that leaves the "
        "credential SAID pointing at a still-issued state, accepts revoked "
        "credentials as valid.",
        {"credential_said": creder_reg.said, "registry": reg.pre,
         "prior_iss_said": iss.said, "dt": FIXED_DT_REVOKE,
         "iss_raw_b64": base64.b64encode(iss.raw).decode(),
         "credential_raw_b64": base64.b64encode(creder_reg.raw).decode()},
        rev,
    ))

    # Before / after as explicit state markers a verifier can check against
    out.append({
        "id": "acdc/revocation-state/before-and-after",
        "kind": "credential",
        "why": "A verifier must know the TEL state of a credential: issued, then "
               "revoked. Capturing both events and their order is what makes an "
               "offline check decide correctly rather than assume 'present means valid'.",
        "input": {
            "credential_said": creder_reg.said,
            "registry": reg.pre,
            "iss_raw_b64": base64.b64encode(iss.raw).decode(),
            "rev_raw_b64": base64.b64encode(rev.raw).decode(),
        },
        "expect": {
            "credential_said": creder_reg.said,
            "before": {
                "ilk": "iss",
                "said": iss.said,
                "raw_b64": base64.b64encode(iss.raw).decode(),
                "state": "issued",
            },
            "after": {
                "ilk": "rev",
                "said": rev.said,
                "raw_b64": base64.b64encode(rev.raw).decode(),
                "prior_said": iss.said,
                "state": "revoked",
            },
        },
    })

    return out


# ---------------------------------------------------------------------------
# Witness receipts
# ---------------------------------------------------------------------------

def receipt_cases():
    out = []

    cur, nxt = signer("a"), signer("b")
    w1, w2, w3 = (
        signer("w", transferable=False),
        signer("x", transferable=False),
        signer("y", transferable=False),
    )
    wits = [w1.verfer.qb64, w2.verfer.qb64, w3.verfer.qb64]
    icp = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)], wits=wits, toad=2,
    )
    # Controller signature on the event (needed for a complete stream later)
    controller_siger = cur.sign(ser=icp.raw, index=0)

    # Receipt body for the inception (one event, many witnesses may sign it)
    rct = eventing.receipt(pre=icp.pre, sn=0, said=icp.said)
    out.append(case(
        "rct/body/for-inception",
        "receipt",
        "A receipt names the event it covers by digest and sequence number. An "
        "implementation that points a receipt at the wrong digest is not covering "
        "the event it thinks it is, and peers will not count it toward the toad.",
        {"prefix": icp.pre, "sn": 0, "event_said": icp.said,
         "event_raw_b64": base64.b64encode(icp.raw).decode(),
         "witnesses": wits, "toad": 2},
        rct,
    ))

    # One witness receipt as a CESR stream (rct + nontrans couple)
    cig1 = w1.sign(ser=icp.raw)
    stream1 = bytes(eventing.messagize(serder=rct, cigars=[cig1]))
    out.append({
        "id": "rct/one-witness",
        "kind": "receipt",
        "why": "A single witness receipt is a stream: the receipt event plus a "
               "non-transferable couple (witness identifier + cigar). Witnesses are "
               "non-transferable, so the identifier IS the verifying key — capture "
               "enough that a checker holding only the key event can verify the cigar.",
        "input": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "event_said": icp.said,
            "prefix": icp.pre,
            "witness": w1.verfer.qb64,
            "cigar_qb64": cig1.qb64,
            "toad": 2,
            "witnesses": wits,
        },
        "expect": {
            "raw_b64": base64.b64encode(stream1).decode(),
            "receipt_raw_b64": base64.b64encode(rct.raw).decode(),
            "receipt_said": rct.said,
            "witness": w1.verfer.qb64,
            "cigar_qb64": cig1.qb64,
            "counter": CtrDex.NonTransReceiptCouples,
            "threshold_met": False,
            "receipt_count": 1,
            "toad": 2,
        },
    })

    # Several witnesses for the same event
    cig2 = w2.sign(ser=icp.raw)
    cig3 = w3.sign(ser=icp.raw)
    stream_multi = bytes(eventing.messagize(serder=rct, cigars=[cig1, cig2, cig3]))
    out.append({
        "id": "rct/three-witnesses",
        "kind": "receipt",
        "why": "Several witnesses sign the same event. The couples are ordered in the "
               "attachment; an implementation that drops one, reorders them, or "
               "deduplicates by key changes whether the toad is met.",
        "input": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "event_said": icp.said,
            "prefix": icp.pre,
            "witnesses": wits,
            "couples": [
                {"witness": w1.verfer.qb64, "cigar_qb64": cig1.qb64},
                {"witness": w2.verfer.qb64, "cigar_qb64": cig2.qb64},
                {"witness": w3.verfer.qb64, "cigar_qb64": cig3.qb64},
            ],
            "toad": 2,
        },
        "expect": {
            "raw_b64": base64.b64encode(stream_multi).decode(),
            "receipt_raw_b64": base64.b64encode(rct.raw).decode(),
            "receipt_said": rct.said,
            "couples": [
                {"witness": w1.verfer.qb64, "cigar_qb64": cig1.qb64},
                {"witness": w2.verfer.qb64, "cigar_qb64": cig2.qb64},
                {"witness": w3.verfer.qb64, "cigar_qb64": cig3.qb64},
            ],
            "counter": CtrDex.NonTransReceiptCouples,
            "threshold_met": True,
            "receipt_count": 3,
            "toad": 2,
        },
    })

    # Threshold met (2 of toad 2) vs not met (1 of toad 2)
    stream_met = bytes(eventing.messagize(serder=rct, cigars=[cig1, cig2]))
    out.append({
        "id": "rct/threshold/met",
        "kind": "receipt",
        "why": "The toad is met when enough designated witnesses have signed. An "
               "implementation that miscounts, or that counts signatures from keys "
               "not in the witness list, accepts events that are not fully witnessed.",
        "input": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "event_said": icp.said,
            "witnesses": wits,
            "toad": 2,
            "signing_witnesses": [w1.verfer.qb64, w2.verfer.qb64],
            "couples": [
                {"witness": w1.verfer.qb64, "cigar_qb64": cig1.qb64},
                {"witness": w2.verfer.qb64, "cigar_qb64": cig2.qb64},
            ],
        },
        "expect": {
            "raw_b64": base64.b64encode(stream_met).decode(),
            "threshold_met": True,
            "receipt_count": 2,
            "toad": 2,
        },
    })
    stream_unmet = bytes(eventing.messagize(serder=rct, cigars=[cig1]))
    out.append({
        "id": "rct/threshold/not-met",
        "kind": "receipt",
        "why": "One receipt against a toad of two is not enough. Treating it as met "
               "lets an event proceed without the witness protection the identity "
               "committed to at inception.",
        "input": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "event_said": icp.said,
            "witnesses": wits,
            "toad": 2,
            "signing_witnesses": [w1.verfer.qb64],
            "couples": [
                {"witness": w1.verfer.qb64, "cigar_qb64": cig1.qb64},
            ],
        },
        "expect": {
            "raw_b64": base64.b64encode(stream_unmet).decode(),
            "threshold_met": False,
            "receipt_count": 1,
            "toad": 2,
        },
    })

    # Refusal: signature does not verify (tamper the cigar material)
    bad_stream = bytearray(stream1)
    # Flip a byte in the attachment (after the receipt JSON)
    attach_at = len(rct.raw)
    if attach_at + 20 < len(bad_stream):
        bad_stream[attach_at + 15] ^= 0x01
    out.append(reject_case(
        "reject/receipt-signature-invalid",
        "A receipt whose signature does not verify must be refused. Accepting it "
        "counts a witness vote that was never cast, and the toad becomes meaningless.",
        bytes(bad_stream),
        because="the witness cigar does not verify under the witness identifier",
        extra_input={
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "event_said": icp.said,
            "witness": w1.verfer.qb64,
            "good_stream_raw_b64": base64.b64encode(stream1).decode(),
        },
    ))

    # Refusal: receipt from a witness the identity never designated
    stranger = signer("stranger", transferable=False)
    stranger_cig = stranger.sign(ser=icp.raw)
    stranger_stream = bytes(eventing.messagize(serder=rct, cigars=[stranger_cig]))
    out.append({
        "id": "reject/receipt-from-undesignated-witness",
        "kind": "reject",
        "why": "Only witnesses named at establishment may contribute to the toad. A "
               "receipt from anyone else must be refused — otherwise an attacker "
               "supplies as many 'witnesses' as they need.",
        "input": {
            "raw_b64": base64.b64encode(stranger_stream).decode(),
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "event_said": icp.said,
            "designated_witnesses": wits,
            "stranger": stranger.verfer.qb64,
            "because": "the signing identifier is not in the event's witness list",
        },
        "expect": {
            "refused": True,
            "because": "the signing identifier is not in the event's witness list",
        },
    })

    # Carry the controller siger so stream cases can compose with this event
    out.append({
        "id": "rct/context/event-and-controller-sig",
        "kind": "receipt",
        "why": "Receipts are checked against a specific event. Capturing the event "
               "bytes and the controller signature together is what lets a later "
               "implementation verify 'this is the event, this is who ran it, these "
               "are the witnesses' without inventing any of the three.",
        "input": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "witnesses": wits,
            "toad": 2,
        },
        "expect": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "event_said": icp.said,
            "aid": icp.pre,
            "controller_siger_qb64": controller_siger.qb64,
            "controller_key": cur.verfer.qb64,
            "toad": 2,
            "witnesses": wits,
        },
    })

    return out


# ---------------------------------------------------------------------------
# CESR attachments and streams
# ---------------------------------------------------------------------------

def stream_cases():
    out = []

    cur, nxt = signer("a"), signer("b")
    w1, w2 = signer("w", transferable=False), signer("x", transferable=False)
    icp = eventing.incept(
        keys=[cur.verfer.qb64], ndigs=[dig(nxt)],
        wits=[w1.verfer.qb64, w2.verfer.qb64], toad=1,
    )
    siger = cur.sign(ser=icp.raw, index=0)
    cig1 = w1.sign(ser=icp.raw)
    cig2 = w2.sign(ser=icp.raw)

    # Event + one controller signature
    stream_one = bytes(eventing.messagize(serder=icp, sigers=[siger]))
    out.append({
        "id": "stream/controller-sig/single",
        "kind": "stream",
        "why": "Events travel with their controller signature attached in a counted "
               "CESR stream. An implementation that can build events but cannot parse "
               "the attachment cannot accept anything that arrives on the wire.",
        "input": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "controller_keys": [cur.verfer.qb64],
            "sigers_qb64": [siger.qb64],
        },
        "expect": {
            "raw_b64": base64.b64encode(stream_one).decode(),
            "event_said": icp.said,
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "attachment_b64": base64.b64encode(stream_one[len(icp.raw):]).decode(),
            "counters": [
                {"code": CtrDex.ControllerIdxSigs, "name": "ControllerIdxSigs"},
            ],
            "signature_count": 1,
        },
    })

    # Multi-controller signatures (2-of-3)
    k1, k2, k3 = signer("m"), signer("n"), signer("o")
    n1, n2, n3 = signer("p"), signer("q"), signer("r")
    icp3 = eventing.incept(
        keys=[k1.verfer.qb64, k2.verfer.qb64, k3.verfer.qb64],
        ndigs=[dig(n1), dig(n2), dig(n3)],
        isith="2", nsith="2",
    )
    sigers3 = [k1.sign(ser=icp3.raw, index=0), k2.sign(ser=icp3.raw, index=1)]
    stream_multi = bytes(eventing.messagize(serder=icp3, sigers=sigers3))
    out.append({
        "id": "stream/controller-sig/two-of-three",
        "kind": "stream",
        "why": "A multi-key identity attaches one indexed signature per signing key. "
               "Losing the index, reordering the sigers, or requiring all keys when "
               "the threshold is 2-of-3 breaks every multi-sig exchange.",
        "input": {
            "event_raw_b64": base64.b64encode(icp3.raw).decode(),
            "controller_keys": [k1.verfer.qb64, k2.verfer.qb64, k3.verfer.qb64],
            "isith": "2",
            "sigers_qb64": [s.qb64 for s in sigers3],
            "indices": [0, 1],
        },
        "expect": {
            "raw_b64": base64.b64encode(stream_multi).decode(),
            "event_said": icp3.said,
            "event_raw_b64": base64.b64encode(icp3.raw).decode(),
            "attachment_b64": base64.b64encode(stream_multi[len(icp3.raw):]).decode(),
            "counters": [
                {"code": CtrDex.ControllerIdxSigs, "name": "ControllerIdxSigs"},
            ],
            "signature_count": 2,
            "indices": [0, 1],
        },
    })

    # Event + controller sig + witness receipt couples
    stream_wit = bytes(eventing.messagize(
        serder=icp, sigers=[siger], cigars=[cig1, cig2],
    ))
    out.append({
        "id": "stream/controller-sig-and-witness-receipts",
        "kind": "stream",
        "why": "A fully witnessed message carries the controller signature group and "
               "the non-transferable receipt couples in one stream. The counter codes "
               "that introduce each group (-A, -C) are how a parser knows what follows; "
               "getting them wrong makes the rest of the stream unreadable.",
        "input": {
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "controller_keys": [cur.verfer.qb64],
            "witnesses": [w1.verfer.qb64, w2.verfer.qb64],
            "sigers_qb64": [siger.qb64],
            "cigars_qb64": [cig1.qb64, cig2.qb64],
        },
        "expect": {
            "raw_b64": base64.b64encode(stream_wit).decode(),
            "event_said": icp.said,
            "event_raw_b64": base64.b64encode(icp.raw).decode(),
            "attachment_b64": base64.b64encode(stream_wit[len(icp.raw):]).decode(),
            "counters": [
                {"code": CtrDex.ControllerIdxSigs, "name": "ControllerIdxSigs"},
                {"code": CtrDex.NonTransReceiptCouples, "name": "NonTransReceiptCouples"},
            ],
            "signature_count": 1,
            "receipt_count": 2,
        },
    })

    # Counter codes alone — explicit so a stream parser can be written against them
    out.append({
        "id": "stream/counter-codes",
        "kind": "constants",
        "why": "Attachment groups are introduced by fixed CESR counter codes. An "
               "implementation that invents its own introducers cannot exchange "
               "signed events with any other KERI implementation.",
        "input": {},
        "expect": {
            "ControllerIdxSigs": CtrDex.ControllerIdxSigs,
            "WitnessIdxSigs": CtrDex.WitnessIdxSigs,
            "NonTransReceiptCouples": CtrDex.NonTransReceiptCouples,
            "TransReceiptQuadruples": CtrDex.TransReceiptQuadruples,
            "AttachedMaterialQuadlets": CtrDex.AttachedMaterialQuadlets,
            "example_stream_starts_with_event": True,
            "example_attachment_prefix": bytes(stream_one[len(icp.raw):len(icp.raw)+4]).decode(),
        },
    })

    # Truncated stream — refusal
    truncated = stream_one[:-8]
    out.append(reject_case(
        "reject/stream-truncated",
        "A truncated CESR stream must be refused. Accepting a partial attachment "
        "treats a missing signature as present, or fails later in a way that looks "
        "like a different bug.",
        truncated,
        because="the stream ends before the attached material is complete",
        extra_input={
            "full_stream_raw_b64": base64.b64encode(stream_one).decode(),
            "event_said": icp.said,
        },
    ))

    return out


def main():
    cases = []
    cases += cesr_code_cases()
    cases += inception_cases()
    cases += rotation_cases()
    cases += interaction_cases()
    cases += delegation_cases()
    cases += credential_cases()
    cases += receipt_cases()
    cases += stream_cases()
    cases += identifier_property_cases()
    cases += rejection_cases()

    # Stable order, unique ids — a duplicate id is a generator bug, not a vector.
    seen = set()
    for c in cases:
        if c["id"] in seen:
            raise SystemExit(f"duplicate case id: {c['id']}")
        seen.add(c["id"])
        if not c.get("why"):
            raise SystemExit(f"case {c['id']} has no why")

    doc = {
        "vector_version": VECTOR_VERSION,
        "oracle": f"keripy {getattr(__import__('keri'), '__version__', 'unknown')}",
        "what_this_is":
            "Fixed answers every conformant KERI implementation must reproduce "
            "byte for byte. Generated from keripy, which the KERI implementations "
            "table lists at 100% spec compliance. Regenerate rather than edit: a "
            "hand-edited expectation is a belief, not a reference.",
        "how_to_use":
            "Run every implementation against every case. raw_b64 is the "
            "authoritative serialisation — the readable event is for humans and its "
            "key order is not the order that was signed.",
        "cases": cases,
    }
    json.dump(doc, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
