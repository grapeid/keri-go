"""Exchange messages (exn), built and judged by keripy.

keripy 1.3.6 builds each message with `exchanging.exchange`, signs it as a
non-transferable identifier (the sender IS its Ed25519 key, so the signature is
the couple keripy's Exchanger reads without any key log), and then a real
`Exchanger` fed through the real `Parser` must take it. A copy with one
signature character changed, a copy signed by another key, and a copy with a
character of the content changed must each be refused by keripy before they are
written down as refusals. keri-go's exchange_test.go reads the file this writes
and must reach every one of the same verdicts and build the same bytes.

    python vectors/generate_exchange_vectors.py > vectors/keri_exchange_vectors_keripy-1.3.6.json

Needs keripy 1.3.6 (Python 3.12 or later).
"""

import json
import sys

import keri
from keri.core import coring, eventing, parsing, signing  # eventing first: keripy has an import cycle
from keri.core.coring import MtrDex
from keri.db import basing
from types import SimpleNamespace
from keri.peer import exchanging

ROUTE = "/test/route"


def signer(tag):
    raw = ((tag * 32)[:32]).encode()
    return signing.Signer(raw=raw, code=MtrDex.Ed25519_Seed, transferable=False)


class Taker:
    """A route handler that records what keripy handed it."""

    resource = ROUTE

    def __init__(self):
        self.taken = []

    def verify(self, serder, **kwargs):
        return True

    def handle(self, serder, **kwargs):
        self.taken.append(serder.said)


def keripy_takes(stream):
    """Whether a real Exchanger, fed by the real Parser, takes the stream."""
    # Only the database is used by an Exchanger taking a non-transferable
    # sender, so the identifiers of a Habery are not needed (and cost seconds).
    with basing.openDB(name="exchange", temp=True) as db:
        taker = Taker()
        exc = exchanging.Exchanger(hby=SimpleNamespace(db=db), handlers=[taker])
        # Step the parser a bounded number of times. Given a message that is
        # refused, or one cut short, it waits for more input and never ends.
        steps = parsing.Parser().allParsator(ims=bytearray(stream), framed=True, exc=exc)
        for _ in range(200):
            try:
                next(steps)
            except StopIteration:
                break
            except Exception:
                break
        return bool(taker.taken)


def build(sender, recipient, prior, dt, route, payload, modifiers=None):
    serder, _ = exchanging.exchange(
        route=route, sender=sender.verfer.qb64, recipient=recipient or None,
        dig=prior or None, date=dt, payload=payload, modifiers=modifiers)
    return serder


def signed_stream(serder, sgnr):
    cigar = sgnr.sign(serder.raw)
    couple = core_counter() + sgnr.verfer.qb64b + cigar.qb64b
    return bytes(serder.raw) + couple


def core_counter():
    from keri.core import Counter, Codens
    from keri import kering
    return Counter(Codens.NonTransReceiptCouples, count=1,
                   gvrsn=kering.Vrsn_1_0).qb64b


def case(name, sender_tag, recipient, prior, dt, route, payload, modifiers=None):
    s = signer(sender_tag)
    serder = build(s, recipient, prior, dt, route, payload, modifiers)
    stream = signed_stream(serder, s)
    return s, serder, stream


def main():
    cases = []
    spec = [
        ("a message with a recipient and content", "a", "EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvB", "",
         "2026-11-14T12:00:00.000000+00:00", ROUTE, {"kind": "ask", "n": 1}),
        ("a message to nobody in particular", "b", "", "",
         "2026-11-14T12:00:01.000000+00:00", ROUTE, {"kind": "note"}),
        ("a message that follows another", "c", "EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvB",
         "EKkPEUZ6Ihm-JvBBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0",
         "2026-11-14T12:00:02.000000+00:00", ROUTE, {"kind": "reply", "words": "a < b & c > d"}),
        ("a message with no content", "d", "EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvB", "",
         "2026-11-14T12:00:03.000000+00:00", ROUTE, {}),
    ]
    for name, tag, rp, p, dt, route, payload in spec:
        s, serder, stream = case(name, tag, rp, p, dt, route, payload)
        if not keripy_takes(stream):
            sys.exit(f"keripy did not take its own message: {name}")
        cases.append({
            "name": name,
            "input": {"sender_seed_tag": tag, "recipient": rp, "prior": p, "dt": dt,
                      "route": route, "data": json.dumps(payload, separators=(",", ":"))},
            "sender": s.verfer.qb64,
            "said": serder.said,
            "raw": serder.raw.decode(),
            "stream": stream.decode(),
            "keripy_takes": True,
        })

    refusals = []
    s, serder, stream = case("base", "e", "EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvB", "",
                             "2026-11-14T12:00:00.000000+00:00", ROUTE, {"kind": "ask"})
    raw = serder.raw

    def refused(name, stream_bytes):
        if keripy_takes(stream_bytes):
            sys.exit(f"keripy took what should be refused: {name}")
        refusals.append({"name": name, "stream": stream_bytes.decode(), "keripy_takes": False})

    sigpos = len(raw) + 4 + 44 + 10
    bad = bytearray(stream)
    bad[sigpos] = ord("A") if bad[sigpos] != ord("A") else ord("B")
    refused("one character of the signature changed", bytes(bad))

    other = signer("f")
    cigar = other.sign(raw)
    refused("signed by a key that is not the sender's",
            bytes(raw) + core_counter() + s.verfer.qb64b + cigar.qb64b)
    refused("a couple naming another sender, correctly signed",
            bytes(raw) + core_counter() + other.verfer.qb64b + cigar.qb64b)

    changed = bytes(stream).replace(b'"kind":"ask"', b'"kind":"asx"', 1)
    refused("a character of the content changed after signing", changed)

    refused("no signature at all", bytes(raw))

    json.dump({"version": 1, "keripy": keri.__version__, "cases": cases,
               "refusals": refusals}, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
