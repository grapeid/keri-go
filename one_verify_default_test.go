//go:build !kerigo_pqtest

package keri

import (
	"crypto/rand"
	"testing"
)

// A default build refuses a post-quantum key at the one check, and its
// signature with it, whatever the signature is.
func TestADefaultBuildRefusesAPostQuantumKeyAtTheOneCheck(t *testing.T) {
	raw := make([]byte, 1952)
	_, _ = rand.Read(raw)
	key, err := MatterQB64Sized("2AAE", raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 3309)
	if VerifyUnderKey(key, []byte("m"), "", sig) == nil || VerifyUnderKey(key, []byte("m"), "3Z", sig) == nil ||
		VerifySignature(key, []byte("m"), sig) == nil {
		t.Fatal("a default build verified under a post-quantum key")
	}
	ed, _ := GenerateSigner(true)
	edKey, _ := ed.PublicKey()
	edSig, _ := ed.Sign([]byte("m"))
	if err := VerifyUnderKey(edKey, []byte("m"), "A", edSig); err != nil {
		t.Fatal(err)
	}
	if VerifyUnderKey(edKey, []byte("m"), "", make([]byte, 64)) == nil {
		t.Fatal("a forged Ed25519 signature verified")
	}
}
