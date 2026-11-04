//go:build kerigo_pqtest

package keri

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type pqSigner struct {
	pk  *mldsa65.PublicKey
	sk  *mldsa65.PrivateKey
	key string
}

func newPQSigner(t *testing.T) pqSigner {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := pk.MarshalBinary()
	key, err := MatterQB64Sized(CodeMLDSA65Key, raw)
	if err != nil || len(key) != 2608 {
		t.Fatalf("an ML-DSA-65 key under its draft code: %d %v", len(key), err)
	}
	return pqSigner{pk, sk, key}
}

func (p pqSigner) sign(t *testing.T, msg []byte, at SignaturePlace) string {
	t.Helper()
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(p.sk, msg, nil, false, sig); err != nil {
		t.Fatal(err)
	}
	q, err := EncodeMLDSA65IndexedSignature(sig, at)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func edSig(t *testing.T, s Signer, msg []byte, at SignaturePlace) string {
	t.Helper()
	raw, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	q, err := EncodeIndexedSignature(raw, at)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func withSigs(t *testing.T, raw []byte, sigs ...string) []byte {
	t.Helper()
	group, err := AttachControllerSigs(sigs)
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), raw...), group...)
}

// Stage two (ADR-061 section 6): keys [Ed25519, ML-DSA-65] with a threshold
// of two verify only with both signatures, under the test build's codes.
func TestAHybridChainVerifiesOnlyWithBothSignatures(t *testing.T) {
	ed, _ := GenerateSigner(true)
	edKey, _ := ed.PublicKey()
	pq := newPQSigner(t)
	n, _ := GenerateSigner(true)
	nk, _ := n.PublicKey()
	nd, _ := NextDigest(nk)
	icp, err := BuildInception(InceptionInput{Keys: []string{edKey, pq.key}, NextDigests: []string{nd},
		Isith: json.RawMessage(`"2"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	both := withSigs(t, icp, edSig(t, ed, icp, SamePlace(0)), pq.sign(t, icp, SamePlace(1)))
	if _, err := ValidateSignedKEL([][]byte{both}); err != nil {
		t.Fatalf("a founding both keys signed was refused: %v", err)
	}
	for name, msg := range map[string][]byte{
		"the Ed25519 signature alone":   withSigs(t, icp, edSig(t, ed, icp, SamePlace(0))),
		"the ML-DSA-65 signature alone": withSigs(t, icp, pq.sign(t, icp, SamePlace(1))),
		"an ML-DSA-65 signature at the Ed25519 key's place": withSigs(t, icp,
			edSig(t, ed, icp, SamePlace(0)), pq.sign(t, icp, SamePlace(0))),
		"an Ed25519 signature at the ML-DSA-65 key's place": withSigs(t, icp,
			edSig(t, ed, icp, SamePlace(0)), edSig(t, ed, icp, SamePlace(1))),
	} {
		if _, err := ValidateSignedKEL([][]byte{msg}); err == nil {
			t.Fatalf("%s met a threshold of two", name)
		}
	}
}

// The post-quantum reserve (ADR-061 section 6, stage one): a founding commits
// to the next Ed25519 key and to an ML-DSA-65 key with a threshold of one; a
// rotation revealing the ML-DSA-65 key alone, at place 0, opens commitment 1.
func TestThePostQuantumReserveOpensItsCommitment(t *testing.T) {
	ed, _ := GenerateSigner(true)
	edKey, _ := ed.PublicKey()
	nextEd, _ := GenerateSigner(true)
	nk, _ := nextEd.PublicKey()
	pq := newPQSigner(t)
	d0, _ := NextDigest(nk)
	d1, _ := Blake3SAID([]byte(pq.key))
	icp, err := BuildInception(InceptionInput{Keys: []string{edKey}, NextDigests: []string{d0, d1},
		Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := ParseEvent(icp)
	after, _ := GenerateSigner(true)
	ak, _ := after.PublicKey()
	ad, _ := NextDigest(ak)
	rot, err := BuildRotation(RotationInput{Prefix: ev.Identifier, Keys: []string{pq.key}, PriorSAID: ev.SAID,
		SN: 1, NextDigests: []string{ad}, Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`)})
	if err != nil {
		t.Fatal(err)
	}
	log := [][]byte{withSigs(t, icp, edSig(t, ed, icp, SamePlace(0))),
		withSigs(t, rot, pq.sign(t, rot, SignaturePlace{Index: 0, Ondex: 1}))}
	res, err := ValidateSignedKEL(log)
	if err != nil {
		t.Fatalf("the reserve reveal was refused: %v", err)
	}
	if res.Keys[0] != pq.key {
		t.Fatal("the post-quantum key is not the key in force")
	}
	// Revealed at the wrong commitment it opens nothing.
	wrong := [][]byte{log[0], withSigs(t, rot, pq.sign(t, rot, SamePlace(0)))}
	if _, err := ValidateSignedKEL(wrong); err == nil {
		t.Fatal("the reserve opened a commitment it was not made under")
	}
}

// An ML-DSA-65 signature does not open an Ed25519 commitment, and a current-
// only one opens none.
func TestAPostQuantumSignatureOpensOnlyItsOwnKeysCommitment(t *testing.T) {
	ed, _ := GenerateSigner(true)
	edKey, _ := ed.PublicKey()
	nextEd, _ := GenerateSigner(true)
	nk, _ := nextEd.PublicKey()
	pq := newPQSigner(t)
	d0, _ := NextDigest(nk)
	d1, _ := Blake3SAID([]byte(pq.key))
	icp, _ := BuildInception(InceptionInput{Keys: []string{edKey}, NextDigests: []string{d0, d1},
		Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	ev, _ := ParseEvent(icp)
	after, _ := GenerateSigner(true)
	ak, _ := after.PublicKey()
	ad, _ := NextDigest(ak)
	rot, _ := BuildRotation(RotationInput{Prefix: ev.Identifier, Keys: []string{nk}, PriorSAID: ev.SAID,
		SN: 1, NextDigests: []string{ad}, Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`)})
	founding := withSigs(t, icp, edSig(t, ed, icp, SamePlace(0)))
	// The Ed25519 key revealed, signed by the ML-DSA-65 key: not its signature.
	if _, err := ValidateSignedKEL([][]byte{founding,
		withSigs(t, rot, pq.sign(t, rot, SamePlace(0)))}); err == nil {
		t.Fatal("an ML-DSA-65 signature opened an Ed25519 commitment")
	}
	// The reserve revealed with a current-only signature opens nothing.
	reveal, _ := BuildRotation(RotationInput{Prefix: ev.Identifier, Keys: []string{pq.key}, PriorSAID: ev.SAID,
		SN: 1, NextDigests: []string{ad}, Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`)})
	if _, err := ValidateSignedKEL([][]byte{founding,
		withSigs(t, reveal, pq.sign(t, reveal, SignaturePlace{Index: 0, CurrentOnly: true}))}); err == nil {
		t.Fatal("a current-only signature opened a commitment")
	}
}

// An ML-DSA-65 key of the wrong length, or not in its one spelling, is
// refused in the test build too.
func TestAPostQuantumKeyMustBeWhole(t *testing.T) {
	pq := newPQSigner(t)
	for name, key := range map[string]string{
		"a character short": pq.key[:len(pq.key)-4],
		"a lead byte set":   pq.key[:4] + "B" + pq.key[5:],
	} {
		if _, _, ok := keyCodeOf(key); ok {
			t.Fatalf("an ML-DSA-65 key %s was read", name)
		}
	}
}

// The test build says it is one, and its selftest fails, so it cannot pass
// for a production build.
func TestATestBuildSaysSo(t *testing.T) {
	if !PostQuantumTestCodes() {
		t.Fatal("the test build reads no post-quantum codes")
	}
	if SelfTest().OK() {
		t.Fatal("the test build's selftest passes")
	}
}
