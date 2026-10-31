package keri

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

// Every CESR value has exactly one string. These tests make the other strings
// that decode to the same bytes, and check each is refused.

// respell sets lead bits in the character after the code: the character at
// index len(code). A one-character code leaves 2 lead bits there, a
// two-character code 4. k is the value written into them, so k = 0 is the
// canonical spelling.
func respell(t *testing.T, qb64 string, codeLen, k int) string {
	t.Helper()
	leadBits := 2 * (codeLen % 4)
	v := strings.IndexByte(b64Alphabet, qb64[codeLen])
	if v < 0 {
		t.Fatalf("%q is not base64url at %d", qb64, codeLen)
	}
	v = v&(0x3f>>leadBits) | k<<(6-leadBits)
	return qb64[:codeLen] + string(b64Alphabet[v]) + qb64[codeLen+1:]
}

func TestAKeyHasOneSpelling(t *testing.T) {
	for _, code := range []string{CodeEd25519, CodeEd25519N} {
		pub := bytes.Repeat([]byte{0x5a}, ed25519.PublicKeySize)
		q, err := MatterQB64(code, pub)
		if err != nil {
			t.Fatal(err)
		}
		if raw, err := MatterRaw(code, q, ed25519.PublicKeySize); err != nil || !bytes.Equal(raw, pub) {
			t.Fatalf("the canonical %q key did not read back: %v", code, err)
		}
		for k := 1; k < 4; k++ {
			other := respell(t, q, 1, k)
			if _, err := MatterRaw(code, other, ed25519.PublicKeySize); err == nil {
				t.Errorf("%q with lead bits %d read as the same key as %q", other, k, q)
			}
		}
	}
}

func TestASignatureHasOneSpelling(t *testing.T) {
	sig := bytes.Repeat([]byte{0xa5}, ed25519.SignatureSize)
	q, err := MatterQB64(CodeEd25519Sig, sig)
	if err != nil {
		t.Fatal(err)
	}
	for k := 1; k < 16; k++ {
		other := respell(t, q, 2, k)
		if _, err := MatterRaw(CodeEd25519Sig, other, ed25519.SignatureSize); err == nil {
			t.Errorf("%q with lead bits %d read as the same signature", other, k)
		}
	}
}

func TestAnIndexedSignatureHasOneSpelling(t *testing.T) {
	sig := bytes.Repeat([]byte{0xa5}, ed25519.SignatureSize)
	q, err := indexedSigQB64(sig, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readIndexedSig(q)
	if err != nil || !bytes.Equal(got.Raw, sig) {
		t.Fatalf("the canonical indexed signature did not read back: %v", err)
	}
	for k := 1; k < 16; k++ {
		other := respell(t, q, 2, k)
		if _, err := readIndexedSig(other); err == nil {
			t.Errorf("%q with lead bits %d read as the same indexed signature", other, k)
		}
	}
}

// Wrong lengths, padding, and the line breaks the standard decoder skips.
func TestAValueOfTheWrongShapeIsRefused(t *testing.T) {
	pub := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	q, err := MatterQB64(CodeEd25519N, pub)
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"one short":            q[:43],
		"one long":             q + "A",
		"four long":            q + "AAAA",
		"padded":               q[:43] + "=",
		"line break inside":    q[:20] + "\n" + q[20:],
		"line break appended":  q[:43] + "\n",
		"standard alphabet":    q[:43] + "+",
		"empty after the code": CodeEd25519N,
	} {
		if _, err := MatterRaw(CodeEd25519N, s, ed25519.PublicKeySize); err == nil {
			t.Errorf("%s: %q was read as a key", name, s)
		}
	}
	sig := bytes.Repeat([]byte{0x22}, ed25519.SignatureSize)
	qs, _ := MatterQB64(CodeEd25519Sig, sig)
	for name, s := range map[string]string{
		"one short": qs[:87],
		"one long":  qs + "A",
		"padded":    qs[:86] + "==",
	} {
		if _, err := MatterRaw(CodeEd25519Sig, s, ed25519.SignatureSize); err == nil {
			t.Errorf("signature %s: %q was read", name, s)
		}
		if len(s) == sizeIndexedSig {
			if _, err := readIndexedSig("A" + s[1:]); err == nil {
				t.Errorf("indexed signature %s: %q was read", name, s)
			}
		}
	}
}

// End to end: a controller signature respelled in a signed event no longer
// verifies, where before it did, 15 ways over.
func TestARespelledControllerSignatureIsRefused(t *testing.T) {
	ctrl := mustSigner(t, 'c', true)
	icp, err := BuildInception(InceptionInput{
		Keys: []string{mustPub(t, ctrl)}, NextDigests: []string{mustDigestOf(t, ctrl)},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEvent(icp, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSignedKEL([][]byte{signed.Message}); err != nil {
		t.Fatalf("the canonical signed event was refused: %v", err)
	}
	msg := string(signed.Message)
	sig := msg[len(msg)-sizeIndexedSig:]
	if _, err := readIndexedSig(sig); err != nil {
		t.Fatalf("the signed event does not end in its indexed signature: %v", err)
	}
	for k := 1; k < 16; k++ {
		other := msg[:len(msg)-sizeIndexedSig] + respell(t, sig, 2, k)
		if _, err := ValidateSignedKEL([][]byte{[]byte(other)}); err == nil {
			t.Errorf("the signature respelled with lead bits %d still verified", k)
		}
	}
}
