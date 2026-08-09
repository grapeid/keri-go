"""Capture CESR 2.0 expectations, paired with their 1.0 counterparts.

Why paired: the interesting property of 2.0 is not any single event, it is what
changes and what does not when the SAME inputs are built under the other
version. A self-addressing identifier moves; a basic one does not. Generating
both from one set of inputs is the only way to state that as an expectation
rather than a claim.

Run against two oracles and compare. keripy 1.3.6 is a published release that
can emit 2.0 on request; keripy main (2.0.0-dev6) has made 2.0 its default and
is where 2.0 is actively developed. Agreement between them is what makes these
vectors trustworthy; disagreement is a finding, not something to average.

    python generate_vectors_v2.py > keri_vectors_v2.json
"""

import base64
import json
import sys

import keri
from keri import kering
from keri.core import coring, eventing

try:  # keripy moved the signing primitives out of coring after 1.1
    from keri.core.signing import Salter, Signer  # noqa: F401
except ImportError:  # pragma: no cover
    from keri.core.coring import Salter, Signer  # noqa: F401

VECTOR_VERSION = 2


def signer(tag: str, transferable: bool = True) -> "Signer":
    """A deterministic key, matching the 1.0 generator's scheme exactly.

    Same derivation as generate_vectors.py on purpose: the pairs are only
    comparable if both versions are built from identical key material.
    """
    raw = ((tag * 32)[:32]).encode()
    return Signer(raw=raw, code=coring.MtrDex.Ed25519_Seed, transferable=transferable)


def dig(s: "Signer") -> str:
    """The pre-rotation commitment: a digest of the NEXT key, never the key."""
    return coring.Diger(ser=s.verfer.qb64.encode()).qb64


WITS = [
    signer(w, transferable=False).verfer.qb64 for w in ("w", "x", "y")
]


def both(builder):
    """Build the same inputs under each version and return the pair."""
    return {
        "1.0": builder(kering.Vrsn_1_0),
        "2.0": builder(kering.Vrsn_2_0),
    }


def expectation(serder):
    return {
        "raw_b64": base64.b64encode(serder.raw).decode(),
        "said": serder.said,
        "aid": serder.pre,
        "version_string": serder.ked["v"],
        "size": len(serder.raw),
        "event_readable": serder.ked,
    }


def case(cid, kind, why, inputs, builder):
    pair = both(builder)
    v1, v2 = pair["1.0"], pair["2.0"]
    return {
        "id": cid,
        "kind": kind,
        "why": why,
        "input": inputs,
        "expect": {
            "1.0": expectation(v1),
            "2.0": expectation(v2),
        },
        # The whole point of the pairing, stated where a reader cannot miss it.
        "identifier_survives_version_change": v1.pre == v2.pre,
    }


def cases():
    a, b, c, d = (signer(t) for t in "abcd")
    out = []

    out.append(case(
        "icp/single-key/no-witnesses",
        "inception",
        "A single-key identity uses basic derivation: the identifier IS the key, "
        "so it is not a digest of the event and does not move when the version "
        "changes. Every event's own identifier still moves, because that is a digest.",
        {"keys": [a.verfer.qb64], "next_digests": [dig(b)], "derivation": "basic"},
        lambda V: eventing.incept(keys=[a.verfer.qb64], ndigs=[dig(b)], version=V, kind="JSON"),
    ))

    out.append(case(
        "icp/two-keys/self-addressing",
        "inception",
        "The case that decides migration. Two keys means self-addressing derivation: "
        "the identifier is a digest of the inception event, the version string is "
        "inside that event, so the SAME KEYS YIELD A DIFFERENT IDENTITY under 2.0. "
        "This is not a defect to be fixed; it is what the two encodings mean.",
        {"keys": [a.verfer.qb64, b.verfer.qb64], "isith": "2",
         "next_digests": [dig(c), dig(d)], "nsith": "2",
         "derivation": "self-addressing"},
        lambda V: eventing.incept(keys=[a.verfer.qb64, b.verfer.qb64], isith="2",
                                  ndigs=[dig(c), dig(d)], nsith="2", version=V, kind="JSON"),
    ))

    out.append(case(
        "icp/witnesses/derived-threshold",
        "inception",
        "Three witnesses and no stated threshold. The reference derives it from the "
        "witness count under both versions; an implementation that defaults it to "
        "zero produces a valid-looking identity whose witnesses need not agree.",
        {"keys": [a.verfer.qb64], "next_digests": [dig(b)], "witnesses": WITS,
         "derivation": "basic"},
        lambda V: eventing.incept(keys=[a.verfer.qb64], ndigs=[dig(b)], wits=WITS, version=V, kind="JSON"),
    ))

    out.append(case(
        "icp/witnesses/explicit-threshold",
        "inception",
        "An explicitly stated witness threshold, to pin that a stated value is kept "
        "rather than re-derived, and that it is written in hexadecimal in both versions.",
        {"keys": [a.verfer.qb64], "next_digests": [dig(b)], "witnesses": WITS, "toad": 2,
         "derivation": "basic"},
        lambda V: eventing.incept(keys=[a.verfer.qb64], ndigs=[dig(b)], wits=WITS,
                                  toad=2, version=V, kind="JSON"),
    ))

    # A rotation and an interaction need an identity to belong to. Built per
    # version so each chains to a prior event of its own version — a 2.0 event
    # chained to a 1.0 prior would be a mixed key log, which is a separate case.
    def rotation(V):
        icp = eventing.incept(keys=[a.verfer.qb64], ndigs=[dig(b)], version=V, kind="JSON")
        return eventing.rotate(pre=icp.pre, keys=[b.verfer.qb64], dig=icp.said,
                               sn=1, ndigs=[dig(c)], version=V, kind="JSON")

    out.append(case(
        "rot/single-key",
        "rotation",
        "Rotating to the pre-committed next key. The prior event's identifier is "
        "part of the rotation, so a rotation is version-locked to the log it extends.",
        {"keys": ["<b>"], "next_digests": ["<dig c>"], "sn": 1, "chains_to": "its own icp"},
        rotation,
    ))

    def interaction(V):
        icp = eventing.incept(keys=[a.verfer.qb64], ndigs=[dig(b)], version=V, kind="JSON")
        return eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=[], version=V, kind="JSON")

    out.append(case(
        "ixn/no-seals",
        "interaction",
        "An interaction anchors data without changing keys. The version must be "
        "stated explicitly: an interaction that inherits the oracle's default "
        "silently becomes a 2.0 event when built against a 2.0-default build, "
        "which is how this generator produced a wrong vector on its first run.",
        {"sn": 1, "data": [], "chains_to": "its own icp"},
        interaction,
    ))

    def delegated_inception(V):
        delegator = eventing.incept(keys=[a.verfer.qb64], ndigs=[dig(b)], version=V, kind="JSON")
        return eventing.delcept(keys=[c.verfer.qb64], delpre=delegator.pre,
                                ndigs=[dig(d)], version=V, kind="JSON")

    out.append(case(
        "dip/single-key",
        "delegation",
        "A delegated inception is ALWAYS self-addressing, even with one key, because "
        "it must commit to its delegator. So unlike a plain single-key inception, a "
        "dip's identifier does move between versions.",
        {"keys": ["<c>"], "next_digests": ["<dig d>"], "delegator": "<icp a>"},
        delegated_inception,
    ))

    return out


def _default_kind():
    """Which serialisation the oracle would use if not told.

    Worth recording: keripy main changed this to CESR at the same commit that
    changed the default version, so an event built without stating a kind is not
    JSON there.
    """
    import inspect
    return inspect.signature(eventing.incept).parameters["kind"].default


def main():
    payload = {
        "vector_version": VECTOR_VERSION,
        "oracle": f"keripy {keri.__version__}",
        "oracle_default_version": f"{kering.Version.major}.{kering.Version.minor}",
        "oracle_default_kind": _default_kind(),
        "what_this_is":
            "Paired CESR 1.0 and 2.0 expectations built from identical inputs. "
            "Captured from keripy, never typed by hand. The bytes are the "
            "specification: if an implementation disagrees, the implementation is "
            "wrong, and a vector is never edited to make a test pass.",
        "how_to_use":
            "For each case, build the input under each version and compare against "
            "expect['1.0']['raw_b64'] and expect['2.0']['raw_b64'] byte for byte. "
            "Then check identifier_survives_version_change matches what you compute.",
        "cases": cases(),
    }
    json.dump(payload, sys.stdout, indent=1, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
