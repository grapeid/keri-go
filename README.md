# keri-go

A KERI implementation in Go, built against conformance vectors captured from the
reference implementation, and verified against two independent implementations.

```bash
go get github.com/grapeid/keri-go
```

```go
package main

import (
	"fmt"

	keri "github.com/grapeid/keri-go"
)

func main() {
	// Keys live behind an interface, so a signer backed by a secure enclave —
	// which can never reveal its private key — satisfies it just as well.
	store := keri.NewMemoryKeyStore()
	chain, err := keri.NewKeychain(store, "my-identity", 1)
	if err != nil {
		panic(err)
	}

	keys, _ := chain.CurrentKeys()
	next, _ := chain.NextDigests() // the pre-rotation commitment

	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys:        keys,
		NextDigests: next,
	})
	if err != nil {
		panic(err)
	}

	signed, err := keri.SignEvent(icp, chain.Signers()...)
	if err != nil {
		panic(err)
	}

	// What a peer receives is the event plus its attachments. Verifying it
	// establishes the identity and the keys in force.
	state, err := keri.ValidateSignedKEL([][]byte{signed.Message})
	if err != nil {
		panic(err)
	}
	fmt.Println(state.Identifier)
}
```

## Why it exists

KERI identifiers are self-certifying: an identifier IS a digest of the event
that created it. Change one byte of that event and you have a different
identity. So two implementations either produce byte-for-byte identical output
or they cannot interoperate at all. There is no partial credit.

There was no maintained, permissively licensed KERI implementation that can be
linked into a mobile application. The Python one cannot be linked into a phone;
the Rust one is EUPL-1.2, which a mobile app must statically link and therefore
cannot hold at arm's length. Go links on both desktop and mobile, and this fills
that gap.

## What is implemented

| | |
|---|---|
| Key events | inception, rotation, interaction, delegated inception and rotation |
| Thresholds | integer and fractional-weight, including nested weighted sets, for both current and next keys; `SatisfiesThreshold` answers whether signatures at given places meet one |
| Witnesses | witness lists, thresholds, receipts, receipt streams |
| Validation | key-log validation, signature verification against established key state, delegation authority |
| Duplicity | detection of two conflicting events at one sequence number |
| Credentials | ACDC credentials, registries, issuance, revocation, **edge-chain verification** |
| Keys | generation, pre-rotation custody, encrypted-at-rest storage, an interface a hardware signer can satisfy |
| Streams | CESR attachments, and publishing or reading a whole key log |
| Signatures | indexed Ed25519 in all four forms keripy defines: `A` and `2A` (a place in the key list and a place in the prior next-key commitments, the same or apart), `B` and `2B` (the key list only) |

Both CESR 1.0 and 2.0 can be read and built. **1.0 is the default**, because 2.0
is not frozen: two builds of the reference produce different 2.0 bytes, and a
self-addressing identifier minted under one form cannot be re-expressed under
the other. See `version.go`.

## What is not implemented

- **Post-quantum signatures.** Ed25519 only.
- **Transaction receipt quadruples** (the `-D` attachment group).
- **OOBI records**, mailboxes, and witness network transport — this is the event
  layer, not an agent.
- **Serialisations other than JSON.** No CBOR, MessagePack, or native CESR.

## How correctness is established

**Conformance.** `vectors/keri_vectors_v1.json` holds what
[keripy](https://github.com/WebOfTrust/keripy) actually produces — the reference
implementation — captured exactly: canonical bytes, identifiers, and cases that
must be refused. The implementation is written until it reproduces them. **71 of
71 cases pass.**

The file is generated, never hand-written. An expectation somebody typed is a
belief about what the answer should be; a captured one is what the reference
actually does, and only the second is worth checking against.

```bash
python3 -m venv .venv && .venv/bin/pip install "keri==1.3.6"
.venv/bin/python3 vectors/generate_vectors.py > vectors/keri_vectors_v1.json
.venv/bin/python3 vectors/verify_vectors.py vectors/keri_vectors_v1.json
go test ./... -run TestConformance -v
```

**Interoperability.** Conformance is a string comparison. The stricter question
is whether other implementations ACCEPT what this one produces, which runs their
validators over our output. Both do:

```bash
# keripy judges what we build
go run ./interop | .venv/bin/python3 interop/verify_interop.py

# keriox — independent Rust — judges the same
go run ./interop | cargo run --manifest-path interop-keriox/Cargo.toml
```

keriox accepts all fifteen cases, including witness receipts, delegation, a
credential registry, issuance and revocation, and a whole key log published as a
single stream. That matters more than the keripy result, because keripy
generated the vectors this was built against and keriox had no part in
producing anything here.

## Reading a failure

A case nothing implements yet reports as a **skip**. A case answered *wrongly*
fails loudly with both byte strings.

Those are deliberately different. Unimplemented is progress not yet made; wrong
is a claim that the rest of the world is mistaken. A suite reporting them alike
would hide the second among the first, which is how a quiet divergence survives
to production.

Every case carries a `why` explaining what breaks if an implementation gets it
wrong, and that text prints when the case fails — so a failure says what it
means, not only what differed.

## The rule under everything

**The vector file is the specification, and it is never edited to make a test
pass.** If the code disagrees with a vector, the code is wrong; that assumption
is correct almost every time. If somebody genuinely believes a vector is wrong,
that is a finding to raise, not a line to change — a quietly edited expectation
converts a disagreement with the whole KERI ecosystem into one nobody can see.

## Other documents

- `MEASUREMENTS.md` — what this package costs in binary size and parsing time,
  measured against the Rust implementation it replaces.
- `MOBILE.md` — building and binding for iOS and Android, and what is not yet
  proven there.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.

Copyright 2026 Rob Andersen.
