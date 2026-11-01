"""The other direction: keripy builds, keri-go judges.

interop/main.go builds events with keri-go and asks keripy to accept them. That
alone can only show keri-go agreeing with itself about what it emits. Here keripy
1.3.6 builds each rotation shape with its own event builders and its own signer,
judges the log with its own Kevery, and hands the log and that verdict to
keri-go, which must reach the same verdict:

    python interop/keripy_builds.py | go run ./interop/judge

The shapes are the ones whose authority turns on which keys signed: a partial
rotation with a dual-index signature, an augmented rotation as keripy signs it,
nested weighted thresholds for two and three owners, and the refusals (too few
committed keys signing, a wrong prior-next place, an added key alone). Then the
witness-indexed signatures that meet, or only appear to meet, a witness
threshold, and the deliberate divergences: one key or witness counted twice.
"""

import base64
import json
import sys

from keri.core import coring, eventing, indexing, parsing, serdering, signing
from keri.core.coring import MtrDex
from keri.db import basing

_count = 0


def fresh():
    """A new Ed25519 key pair with a seed nothing else here uses."""
    global _count
    _count += 1
    seed = bytes([_count % 256, _count // 256]) + b"\x5a" * 30
    return signing.Signer(raw=seed, transferable=True)


def dig(signer):
    """The next-key commitment to a key: Blake3-256 over its qb64 text."""
    return coring.Diger(ser=signer.verfer.qb64b, code=MtrDex.Blake3_256).qb64


def keripy_verdict(messages, final_said):
    """Feed the log to a fresh Kevery and report whether its last event is
    the identity's latest. A rotation whose signatures fall short is held in
    escrow, never refused outright, so 'not the latest' is a refusal."""
    with basing.openDB(name="keripy-builds", temp=True) as db:
        kvy = eventing.Kevery(db=db, lax=True, local=True)
        for msg in messages:
            parsing.Parser(kvy=kvy).parse(ims=bytearray(msg))
        kvy.processEscrows()
        first = serdering.SerderKERI(raw=bytes(messages[0]))
        kever = kvy.kevers.get(first.pre)
        if kever is None:
            return "refused: nothing was established"
        if kever.serder.said != final_said:
            return f"refused: the log stops at sn {kever.sn}"
        return "accepted"


cases = []


def sign_as(ser, signer, index, ondex, only, code=None):
    """keripy's signer, which picks the code; or, given a code, a signature
    written in that code at those places, as a peer could write it."""
    if code is None:
        return signer.sign(ser, index=index, ondex=ondex, only=only)
    return indexing.Siger(raw=signer.sign(ser).raw, code=code, index=index, ondex=ondex)


def case(label, why, expect, icp_keys, isith, ndigs, nsith, rot_keys, rsith,
         rndigs, rnsith, sigs, divergence=""):
    """Incept on icp_keys, then rotate to rot_keys signed as sigs describes:
    a list of (signer, index, ondex, only[, code]) for sign_as."""
    icp = eventing.incept(keys=[s.verfer.qb64 for s in icp_keys], isith=isith,
                          ndigs=ndigs, nsith=nsith, code=MtrDex.Blake3_256)
    icp_sigs = [s.sign(icp.raw, index=i) for i, s in enumerate(icp_keys)]
    icp_msg = eventing.messagize(icp, sigers=icp_sigs)

    rot = eventing.rotate(pre=icp.pre, keys=[s.verfer.qb64 for s in rot_keys],
                          dig=icp.said, sn=1, isith=rsith, ndigs=rndigs,
                          nsith=rnsith)
    rot_sigs = [sign_as(rot.raw, *sig) for sig in sigs]
    rot_msg = eventing.messagize(rot, sigers=rot_sigs)

    messages = [bytes(icp_msg), bytes(rot_msg)]
    cases.append({
        "label": label,
        "why": why,
        "expect": expect,
        "codes": [sg.code for sg in rot_sigs],
        "messages_b64": [base64.b64encode(m).decode() for m in messages],
        "keripy": keripy_verdict(messages, rot.said),
        "divergence": divergence,
    })


def icp_case(label, why, expect, keys, isith, ndigs, nsith, signing=None, divergence=""):
    """An inception alone, signed by the keys at the places in signing
    (default: every key at its own place)."""
    icp = eventing.incept(keys=[s.verfer.qb64 for s in keys], isith=isith,
                          ndigs=ndigs, nsith=nsith, code=MtrDex.Blake3_256)
    places = range(len(keys)) if signing is None else signing
    sigs = [keys[i].sign(icp.raw, index=i) for i in places]
    msg = bytes(eventing.messagize(icp, sigers=sigs))
    cases.append({
        "label": label, "why": why, "expect": expect,
        "codes": [sg.code for sg in sigs],
        "messages_b64": [base64.b64encode(msg).decode()],
        "keripy": keripy_verdict([msg], icp.said),
        "divergence": divergence,
    })


def witnessed_case(label, why, expect, wits, toad, wsigs, divergence=""):
    """An inception on one key with witnesses wits and threshold toad, carrying
    witness-indexed signatures: a list of (witness, index, code)."""
    a, e = fresh(), fresh()
    icp = eventing.incept(keys=[a.verfer.qb64], isith="1", ndigs=[dig(e)], nsith="1",
                          wits=[w.verfer.qb64 for w in wits], toad=toad,
                          code=MtrDex.Blake3_256)
    wigers = [indexing.Siger(raw=w.sign(icp.raw).raw, code=code, index=i)
              for (w, i, code) in wsigs]
    msg = bytes(eventing.messagize(icp, sigers=[a.sign(icp.raw, index=0)], wigers=wigers))
    cases.append({
        "label": label, "why": why, "expect": expect,
        "codes": [wg.code for wg in wigers],
        "messages_b64": [base64.b64encode(msg).decode()],
        "keripy": keripy_verdict([msg], icp.said),
        "divergence": divergence,
    })


def witness(tag):
    """A non-transferable witness key pair."""
    return signing.Signer(raw=bytes([tag]) * 32, transferable=False)


def main():
    accepted, refused = "accepted", "refused"

    # One owner, two commitments, nt = 1: reveal the second alone at k[0].
    o, other, c, after = fresh(), fresh(), fresh(), fresh()
    case("partial-dual-index", "reveal n[1] at k[0]; keripy writes 2A", accepted,
         [o], "1", [dig(other), dig(c)], "1",
         [c], "1", [dig(after)], "1", [(c, 0, 1, False)])

    o, other, c, after = fresh(), fresh(), fresh(), fresh()
    case("wrong-prior-place", "the same reveal signed as if it opened n[0]", refused,
         [o], "1", [dig(other), dig(c)], "1",
         [c], "1", [dig(after)], "1", [(c, 0, 0, False)])

    o, c, d, after = fresh(), fresh(), fresh(), fresh()
    case("too-few-exposed", "two committed keys listed, nt = 2, one signs", refused,
         [o], "1", [dig(c), dig(d)], "2",
         [c, d], "1", [dig(after)], "1", [(c, 0, None, False)])

    # Augmented: keripy's own signer writes A at every place, including the
    # added key's, which then names a commitment it does not open.
    o, c, added, after = fresh(), fresh(), fresh(), fresh()
    case("augmented", "a key added without commitment, signed as keripy signs it",
         accepted, [o], "1", [dig(c)], "1",
         [c, added], "2", [dig(after)], "1",
         [(c, 0, None, False), (added, 1, None, False)])

    o, c, added, after = fresh(), fresh(), fresh(), fresh()
    case("augmented-current-only", "the added key signs current-only (B)", accepted,
         [o], "1", [dig(c)], "1",
         [c, added], "2", [dig(after)], "1",
         [(c, 0, None, False), (added, 1, None, True)])

    o, c, added, after = fresh(), fresh(), fresh(), fresh()
    case("added-key-alone", "the added key alone signs", refused,
         [o], "1", [dig(c)], "1",
         [c, added], "1", [dig(after)], "1", [(added, 1, None, False)])

    # Two owners, both must act. Owner i: k[i]; n[2i] first, n[2i+1] second.
    two1 = [["1", "1"], ["1", "1"]]
    two2 = [["1/2", "1/2"], ["1/2", "1/2"]]
    owners, n = [fresh(), fresh()], [fresh() for _ in range(4)]
    after = [fresh() for _ in range(4)]
    case("two-owners", "owner 1 at k[1] opens n[2]; keripy writes 2A", accepted,
         owners, "2", [dig(s) for s in n], two1,
         [n[0], n[2]], "2", [dig(s) for s in after], two1,
         [(n[0], 0, 0, False), (n[2], 1, 2, False)])

    owners, n = [fresh(), fresh()], [fresh() for _ in range(4)]
    after = [fresh() for _ in range(4)]
    case("two-owners-one-acts", "owner 0 reveals both keys, owner 1 none", refused,
         owners, "2", [dig(s) for s in n], two1,
         [n[0], n[1]], "1", [dig(s) for s in after], two1,
         [(n[0], 0, 0, False), (n[1], 1, 1, False)])

    owners, n = [fresh(), fresh()], [fresh() for _ in range(4)]
    after = [fresh() for _ in range(4)]
    case("two-owners-stage-two", "both owners reveal both keys", accepted,
         owners, "2", [dig(s) for s in n], two1,
         n, two2, [dig(s) for s in after], two2,
         [(s, i, i, False) for i, s in enumerate(n)])

    # Three owners, any two: a nested set per owner, each weighing 1/2.
    three1 = [{"1/2": ["1", "1"]}, {"1/2": ["1", "1"]}, {"1/2": ["1", "1"]}]
    three2 = [{"1/2": ["1/2", "1/2"]}, {"1/2": ["1/2", "1/2"]}, {"1/2": ["1/2", "1/2"]}]

    def three(label, why, expect, pick, rsith, rnsith_now, sig_places):
        owners, n = [fresh(), fresh(), fresh()], [fresh() for _ in range(6)]
        after = [fresh() for _ in range(6)]
        keys = [n[p] for p in pick]
        case(label, why, expect, owners, "2", [dig(s) for s in n], three1,
             keys, rsith, [dig(s) for s in after], rnsith_now,
             [(n[p], i, o, False) for (p, i, o) in sig_places])

    three("three-owners", "owners 0 and 2, first keys; owner 2 opens n[4] at k[1]",
          accepted, [0, 4], "2", three1, [(0, 0, 0), (4, 1, 4)])
    three("three-owners-second-key", "owner 0's first key with owner 2's second, n[5]",
          accepted, [0, 5], "2", three1, [(0, 0, 0), (5, 1, 5)])
    three("three-owners-one-acts", "owner 0's two keys alone", refused,
          [0, 1], "2", three1, [(0, 0, 0), (1, 1, 1)])
    three("three-owners-stage-two", "owners 0 and 2, both keys each, nested kt",
          accepted, [0, 1, 2, 3, 4, 5], three2, three2,
          [(0, 0, 0), (1, 1, 1), (4, 4, 4), (5, 5, 5)])

    # A signature that does not verify: made by the founding key, claiming
    # d's place. Dropped and the rest judged; it never counts.
    o, c, d, after = fresh(), fresh(), fresh(), fresh()
    case("junk-signature", "a valid rotation plus a signature that does not verify",
         accepted, [o], "1", [dig(c), dig(d)], "1",
         [c, d], "1", [dig(after)], "1", [(c, 0, None, False), (o, 1, None, False)])
    o, c, d, after = fresh(), fresh(), fresh(), fresh()
    case("junk-signature-counted", "kt = 2 met only if the junk signature counted",
         refused, [o], "1", [dig(c), dig(d)], "1",
         [c, d], "2", [dig(after)], "1", [(c, 0, None, False), (o, 1, None, False)])

    # Thresholds keripy accepts that are easy to refuse by mistake: fewer
    # weights than keys (the extra keys weigh nothing, and one signing makes
    # the threshold unmet), and a next threshold of zero over commitments.
    a, b, c, e = fresh(), fresh(), fresh(), fresh()
    icp_case("fewer-weights-than-keys", "three keys, kt [1/2, 1/2], the first two sign",
             accepted, [a, b, c], ["1/2", "1/2"], [dig(e)], "1", signing=[0, 1])
    a, b, c, e = fresh(), fresh(), fresh(), fresh()
    icp_case("unweighted-key-signs", "three keys, kt [1/2, 1/2], all three sign",
             refused, [a, b, c], ["1/2", "1/2"], [dig(e)], "1")
    a, e = fresh(), fresh()
    icp_case("next-threshold-zero", "nt 0 over one commitment: abandoned at founding",
             accepted, [a], "1", [dig(e)], "0")

    # Where keri-go deliberately differs. keripy counts a place once per
    # verified signature and removes only byte-identical signatures, so one key
    # signing at one place in two spellings counts twice: it meets kt = 2, or a
    # prior nt = 2, alone. keripy accepts these; keri-go must refuse them.
    same_key_twice = ("one key written in two spellings counts once in keri-go; "
                      "keripy counts it twice")
    o, c, d, e = fresh(), fresh(), fresh(), fresh()
    case("one-key-meets-kt-twice", "kt = 2 over [c, d]; only c signs, as A and B",
         accepted, [o], "1", [dig(c)], "1",
         [c, d], "2", [dig(e)], "1", [(c, 0, None, False), (c, 0, None, True)],
         divergence=same_key_twice)
    o, c, d, e = fresh(), fresh(), fresh(), fresh()
    case("one-key-opens-twice", "prior nt = 2 over [c, d]; only c signs, as A and 2A(0,0)",
         accepted, [o], "1", [dig(c), dig(d)], "2",
         [c, d], "1", [dig(e)], "1", [(c, 0, None, False), (c, 0, 0, False, "2A")],
         divergence=same_key_twice)

    # One key written twice in a key list is two places, each opened honestly,
    # so counting each signature once does not help: the list itself must be
    # refused. keripy accepts both.
    listed_twice = ("a key list naming one key twice is refused by keri-go; "
                    "keripy accepts it and counts the key at both places")
    a, e = fresh(), fresh()
    icp_case("one-key-listed-twice", "k = [a, a], kt = 2; a signs at both places",
             accepted, [a, a], "2", [dig(e)], "1", signing=[0, 1],
             divergence=listed_twice)
    o, c, e = fresh(), fresh(), fresh()
    case("one-key-committed-twice",
         "n = [H(c), H(c)], nt = 2; c alone opens both, as 2A(0,0) and 2A(0,1)",
         accepted, [o], "1", [dig(c), dig(c)], "2",
         [c], "1", [dig(e)], "1", [(c, 0, 0, False, "2A"), (c, 0, 1, False, "2A")],
         divergence=listed_twice)

    # Witness-indexed signatures. keripy counts one witness's signature twice
    # when it is attached under two codes (the bytes are identical, so anyone
    # holding the receipt can do it); keri-go counts each witness once.
    A, B = indexing.IdrDex.Ed25519_Sig, indexing.IdrDex.Ed25519_Crt_Sig
    w1, w2 = witness(0x31), witness(0x32)
    witnessed_case("two-witnesses", "toad = 2 over [w1, w2]; both witnesses sign",
                   accepted, [w1, w2], 2, [(w1, 0, A), (w2, 1, A)])
    witnessed_case("one-witness-re-encoded", "toad = 2 over [w1, w2]; w1 alone, as A0 and B0",
                   accepted, [w1, w2], 2, [(w1, 0, A), (w1, 0, B)],
                   divergence=("one witness written in two spellings counts once in "
                               "keri-go; keripy counts it twice"))
    witnessed_case("one-witness", "toad = 2 over [w1, w2]; w1 alone, once",
                   refused, [w1, w2], 2, [(w1, 0, A)])

    # Every case must be judged by keripy as the case says, or the shape
    # tested is not the shape described.
    for c in cases:
        got = "accepted" if c["keripy"] == "accepted" else "refused"
        if got != c["expect"]:
            sys.exit(f"keripy judged {c['label']} {c['keripy']}, the case expects {c['expect']}")

    json.dump(cases, sys.stdout)


if __name__ == "__main__":
    main()
