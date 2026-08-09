# keri-go

A KERI event layer in Go, built against conformance vectors captured from the
reference implementation.

## Why it exists

KERI identifiers are self-certifying: an identifier IS a digest of the event
that created it. Change one byte of that event and you have a different
identity. So two implementations of KERI either produce byte-for-byte identical
output or they cannot interoperate at all. There is no partial credit.

There is no maintained, permissively licensed KERI implementation that can be
linked into a mobile application. The complete Python one cannot be linked into
a phone; the complete Rust one is EUPL-1.2, which a mobile app must statically
link and therefore cannot hold at arm's length. Go can be linked on both
desktop and mobile, and this fills that gap.

## How it is built

The answers come first.

`vectors/keri_vectors_v1.json` holds what [keripy](https://github.com/WebOfTrust/keripy)
actually produces — the reference implementation, listed at 100% spec
compliance — captured exactly: canonical bytes, identifiers, and the cases that
must be refused. The implementation is then written until it reproduces them.

The file is generated, never hand-written. An expectation somebody typed is a
belief about what the answer should be; a captured one is what the reference
actually does, and only the second is worth checking against.

```bash
python3 -m venv .venv && .venv/bin/pip install "keri==1.1.17"

# regenerate from the reference
.venv/bin/python3 vectors/generate_vectors.py > vectors/keri_vectors_v1.json

# check the vectors still describe what keripy does
.venv/bin/python3 vectors/verify_vectors.py vectors/keri_vectors_v1.json

# check this implementation against them
go test ./... -run TestConformance -v
```

## Reading a failure

A case nothing implements yet reports as a **skip**. A case answered *wrongly*
fails loudly with both byte strings.

Those are deliberately different. Unimplemented is progress not yet made; wrong
is a claim that the rest of the world is mistaken. A suite that reported them
alike would hide the second among the first, which is how a quiet divergence
survives to production.

Every case carries a `why` explaining what breaks if an implementation gets it
wrong, and that text is printed when the case fails — so a failure says what it
means, not only what differed.

## The rule under everything

**The vector file is the specification, and it is never edited to make a test
pass.** If the code disagrees with a vector, the code is wrong; that assumption
is correct almost every time. If somebody genuinely believes a vector is wrong,
that is a finding to raise, not a line to change — a quietly edited expectation
converts a disagreement with the whole KERI ecosystem into one nobody can see.

## State

Interaction events are implemented and conformant. Inception, rotation,
delegation, key-log validation and credential verification are not yet written;
their cases report as unimplemented.

47 vectors so far, covering inception across key counts, thresholds including
fractional weights, witness configurations, both derivation styles, rotation
with witness changes and threshold changes, chained events, sequence-number
formatting at its boundaries, delegation, and seven cases that must be refused.

## Licence

Apache-2.0.
