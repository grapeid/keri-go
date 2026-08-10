// Package keri implements KERI, the Key Event Receipt Infrastructure.
//
// KERI gives an identifier a verifiable history. The identifier is derived from
// the event that created it, so it certifies itself: no registry, no
// certificate authority, and nothing to trust except the events and their
// signatures. Rotating keys, delegating authority, issuing and revoking
// credentials are all recorded as events in a log anyone can check.
//
// # Byte-for-byte or not at all
//
// An identifier IS a digest of its own inception event. Change one byte of that
// event and the identity is different — so two implementations produce
// identical bytes or they cannot interoperate. There is no partial credit, and
// no amount of review substitutes for comparing the bytes.
//
// This package is therefore written against captured expectations rather than
// against a reading of the specification. The vectors in vectors/ hold what the
// reference implementation actually produces, and the implementation is written
// until it reproduces them exactly. Other implementations have then been asked
// to accept what this one builds, which is the stricter question: keripy and
// keriox both do.
//
// # What is here
//
// Building and validating key events — inception, rotation, interaction, and
// delegated forms — with integer and fractional-weight signing thresholds.
// Witness lists, witness receipts, and the thresholds that decide whether
// enough witnesses have agreed. Key logs, validated as a chain and against the
// key state they establish. ACDC credentials with registries, issuance,
// revocation, and verification of an edge chain back to its root. Detection of
// duplicity, where one identifier has signed two different histories.
//
// Keys live behind the [Signer] interface, which asks for a signature and never
// for a key. A signer backed by a secure enclave, a TPM or an HSM cannot export
// its private key, so an interface demanding one would be unusable with all
// three; this one is not. [SoftwareSigner] is the in-process implementation,
// and [FileKeyStore] persists keys encrypted at rest.
//
// [Keychain] manages pre-rotation, which is the property that makes a stolen
// key insufficient to take an identity over: an identity commits to its next
// key by digest, and a rotation must reveal the key that digest names. That
// only holds if the next key is generated in advance, kept secret until it is
// used, and still available when it is needed — so the keychain owns that
// lifecycle rather than leaving it to a caller to remember.
//
// # Versions
//
// Both CESR 1.0 and 2.0 can be read and built, and an event says which it is,
// so reading needs no negotiation. Version 1.0 is the default because 2.0 is
// not frozen: two builds of the reference implementation produce different 2.0
// bytes, and a self-addressing identifier minted under one form cannot be
// re-expressed under the other. See [DefaultVersion].
//
// # What is not here
//
// This is the event layer, not an agent. There is no transport, no mailbox, no
// OOBI resolution and no witness network. Signatures are Ed25519 only, with no
// post-quantum scheme. JSON is the only serialisation; CBOR, MessagePack and
// native CESR encoding are not implemented.
package keri
