//go:build kerigo_pqtest

package keri

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// VerifyUnderKey is the one signature check by key type: it takes each kind of
// key its own kind of signature and refuses a signature whose code does not
// fit the key.
func TestVerifyUnderKeyChoosesTheCheckByTheKeysCode(t *testing.T) {
	msg := []byte("an event")
	ed, _ := GenerateSigner(true)
	edKey, _ := ed.PublicKey()
	edRaw, _ := ed.Sign(msg)
	pq := newPQSigner(t)
	pqRaw := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(pq.sk, msg, nil, false, pqRaw); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Repeat([]byte{1}, len(pqRaw))

	for _, c := range []struct {
		name    string
		key     string
		code    string
		sig     []byte
		verifys bool
	}{
		{"Ed25519 raw", edKey, "", edRaw, true},
		{"Ed25519 indexed A", edKey, "A", edRaw, true},
		{"Ed25519 current-only B", edKey, "B", edRaw, true},
		{"Ed25519 forged", edKey, "", make([]byte, 64), false},
		{"Ed25519 key, post-quantum code", edKey, CodeMLDSA65IndexedSig, edRaw, false},
		{"ML-DSA raw", pq.key, "", pqRaw, true},
		{"ML-DSA indexed", pq.key, CodeMLDSA65IndexedSig, pqRaw, true},
		{"ML-DSA current-only", pq.key, CodeMLDSA65CurrentOnlySig, pqRaw, true},
		{"ML-DSA forged", pq.key, CodeMLDSA65IndexedSig, bad, false},
		{"ML-DSA key, Ed25519 code", pq.key, "A", pqRaw, false},
		{"ML-DSA key, Ed25519 signature", pq.key, "", edRaw, false},
	} {
		if err := VerifyUnderKey(c.key, msg, c.code, c.sig); (err == nil) != c.verifys {
			t.Errorf("%s: verifies=%v, error %v", c.name, c.verifys, err)
		}
	}
	if err := VerifySignature(pq.key, msg, pqRaw); err != nil {
		t.Errorf("VerifySignature, which is VerifyUnderKey, refuses a good post-quantum signature: %v", err)
	}
}
