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
committed keys signing, a wrong prior-next place, an added key alone).
"""

import base64
import json
import sys

from keri.core import coring, eventing, parsing, serdering, signing
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


def case(label, why, expect, icp_keys, isith, ndigs, nsith, rot_keys, rsith,
         rndigs, rnsith, sigs):
    """Incept on icp_keys, then rotate to rot_keys signed as sigs describes:
    a list of (signer, index, ondex, only), passed to keripy's signer as is."""
    icp = eventing.incept(keys=[s.verfer.qb64 for s in icp_keys], isith=isith,
                          ndigs=ndigs, nsith=nsith, code=MtrDex.Blake3_256)
    icp_sigs = [s.sign(icp.raw, index=i) for i, s in enumerate(icp_keys)]
    icp_msg = eventing.messagize(icp, sigers=icp_sigs)

    rot = eventing.rotate(pre=icp.pre, keys=[s.verfer.qb64 for s in rot_keys],
                          dig=icp.said, sn=1, isith=rsith, ndigs=rndigs,
                          nsith=rnsith)
    rot_sigs = [s.sign(rot.raw, index=i, ondex=o, only=only)
                for (s, i, o, only) in sigs]
    rot_msg = eventing.messagize(rot, sigers=rot_sigs)

    messages = [bytes(icp_msg), bytes(rot_msg)]
    cases.append({
        "label": label,
        "why": why,
        "expect": expect,
        "codes": [sg.code for sg in rot_sigs],
        "messages_b64": [base64.b64encode(m).decode() for m in messages],
        "keripy": keripy_verdict(messages, rot.said),
    })


def main():
    accepted, refused = "accepted", "refused"

    # One owner, two commitments, nt = 1: reveal the second alone at k[0].
    o, reserve, c, after = fresh(), fresh(), fresh(), fresh()
    case("partial-dual-index", "reveal n[1] at k[0]; keripy writes 2A", accepted,
         [o], "1", [dig(reserve), dig(c)], "1",
         [c], "1", [dig(after)], "1", [(c, 0, 1, False)])

    o, reserve, c, after = fresh(), fresh(), fresh(), fresh()
    case("wrong-prior-place", "the same reveal signed as if it opened n[0]", refused,
         [o], "1", [dig(reserve), dig(c)], "1",
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

    # Two owners, both must act. Owner i: k[i]; n[2i] classical, n[2i+1] reserve.
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

    three("three-owners", "owners 0 and 2, classical keys; owner 2 opens n[4] at k[1]",
          accepted, [0, 4], "2", three1, [(0, 0, 0), (4, 1, 4)])
    three("three-owners-reserve", "owner 0 classical with owner 2's reserve, n[5]",
          accepted, [0, 5], "2", three1, [(0, 0, 0), (5, 1, 5)])
    three("three-owners-one-acts", "owner 0's two keys alone", refused,
          [0, 1], "2", three1, [(0, 0, 0), (1, 1, 1)])
    three("three-owners-stage-two", "owners 0 and 2, both keys each, nested kt",
          accepted, [0, 1, 2, 3, 4, 5], three2, three2,
          [(0, 0, 0), (1, 1, 1), (4, 4, 4), (5, 5, 5)])

    # Every case must be judged by keripy as the case says, or the shape
    # tested is not the shape described.
    for c in cases:
        got = "accepted" if c["keripy"] == "accepted" else "refused"
        if got != c["expect"]:
            sys.exit(f"keripy judged {c['label']} {c['keripy']}, the case expects {c['expect']}")

    json.dump(cases, sys.stdout)


if __name__ == "__main__":
    main()
