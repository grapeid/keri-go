package keri

import (
	"crypto/ed25519"
	"testing"
)

// An Ed25519 key takes only Ed25519 signature codes, in every build: a
// signature offered under another code (the ML-DSA one, keripy's ECDSA one, or
// one nothing assigns) is refused even when the bytes verify.
func TestAnEd25519KeyTakesOnlyEd25519SignatureCodes(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	key, err := MatterQB64(CodeEd25519, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("a message")
	sig := ed25519.Sign(priv, msg)
	for _, code := range []string{"", "A", "B", "2A", "2B"} {
		if err := VerifyUnderKey(key, msg, code, sig); err != nil {
			t.Errorf("code %q: %v", code, err)
		}
	}
	for _, code := range []string{"3Z", "3Y", "C", "ZZ"} {
		if err := VerifyUnderKey(key, msg, code, sig); err == nil {
			t.Errorf("an Ed25519 signature under code %q was taken", code)
		}
	}
}
