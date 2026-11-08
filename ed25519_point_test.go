package keri

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
)

// The encodings of the eight points of small order.
var smallOrderEd25519Keys = []string{
	"0100000000000000000000000000000000000000000000000000000000000000", // the identity
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
}

// nonCanonicalEd25519 is a second encoding of a point of large order: y
// written as y + p.
func nonCanonicalEd25519(t *testing.T) []byte {
	t.Helper()
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for y := int64(2); y < 19; y++ {
		le := new(big.Int).Add(p, big.NewInt(y)).FillBytes(make([]byte, 32))
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			le[i], le[j] = le[j], le[i]
		}
		pt, err := new(edwards25519.Point).SetBytes(le)
		if err != nil || new(edwards25519.Point).MultByCofactor(pt).Equal(edwards25519.NewIdentityPoint()) == 1 {
			continue
		}
		return le
	}
	t.Fatal("no y below 19 is a point of large order")
	return nil
}

func mustQB64(t *testing.T, code string, raw []byte) string {
	t.Helper()
	q, err := MatterQB64(code, raw)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestAnEd25519KeyIsOnePoint(t *testing.T) {
	good := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if err := CheckEd25519PublicKey(good); err != nil {
		t.Fatalf("a real key was refused: %v", err)
	}
	if err := CheckEd25519PublicKey(good[:31]); err == nil {
		t.Error("a short key was accepted")
	}
	offCurve, _ := hex.DecodeString("0200000000000000000000000000000000000000000000000000000000000000")
	bad := map[string][]byte{
		"off-curve":     offCurve,
		"non-canonical": nonCanonicalEd25519(t),
	}
	for i, h := range smallOrderEd25519Keys {
		raw, _ := hex.DecodeString(h)
		bad[fmt.Sprintf("small-order-%d", i)] = raw
	}
	for name, raw := range bad {
		if err := CheckEd25519PublicKey(raw); err == nil {
			t.Errorf("%s key %x was accepted", name, raw)
		}
		for _, code := range []string{CodeEd25519, CodeEd25519N} {
			q := mustQB64(t, code, raw)
			if _, err := MatterRaw(code, q, ed25519.PublicKeySize); err == nil {
				t.Errorf("%s key %x was read under code %q", name, raw, code)
			}
			if _, _, ok := keyCodeOf(q); ok {
				t.Errorf("%s key %x was taken as a key under code %q", name, raw, code)
			}
		}
		if _, err := witnessKey(mustQB64(t, CodeEd25519N, raw)); err == nil {
			t.Errorf("%s key %x was read as a witness identifier", name, raw)
		}
	}
	if _, err := MatterRaw(CodeEd25519, mustQB64(t, CodeEd25519, good), ed25519.PublicKeySize); err != nil {
		t.Errorf("a real key was refused by MatterRaw: %v", err)
	}
	// A 32-byte value under another code (a digest) is not a key and is untouched.
	if _, err := MatterRaw(CodeBlake3_256, mustQB64(t, CodeBlake3_256, make([]byte, 32)), 32); err != nil {
		t.Errorf("a digest was refused: %v", err)
	}
}

// A signature of all-but-the-first-byte zeros (R = the identity, S = 0) under
// the identity key verifies over every message in Go's verifier. VerifyUnderKey
// must refuse it because the key is refused, not because the signature fails.
func TestASmallOrderKeySignsNothing(t *testing.T) {
	identity, _ := hex.DecodeString(smallOrderEd25519Keys[0])
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 1
	if !ed25519.Verify(identity, []byte("any message"), sig) {
		t.Skip("this Go verifier does not accept the identity-key signature; the premise is gone")
	}
	for _, code := range []string{CodeEd25519, CodeEd25519N} {
		if err := VerifyUnderKey(mustQB64(t, code, identity), []byte("any message"), "", sig); err == nil {
			t.Errorf("a signature under the identity key was accepted under code %q", code)
		}
	}
}
