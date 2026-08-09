package keri

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadSignedKEL(t *testing.T) map[string][][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("vectors", "signed_kel_fixture.json"))
	if err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string][][]byte{}
	for k, v := range raw {
		var msgs []string
		if json.Unmarshal(v, &msgs) != nil {
			continue // the scalar fields
		}
		decoded := make([][]byte, len(msgs))
		for i, s := range msgs {
			d, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				t.Fatal(err)
			}
			decoded[i] = d
		}
		out[k] = decoded
	}
	return out
}

func TestASignedLogVerifiesAgainstTheKeysItEstablishes(t *testing.T) {
	f := loadSignedKEL(t)
	res, err := ValidateSignedKEL(f["good"])
	if err != nil {
		t.Fatalf("a correctly signed log was refused: %v", err)
	}
	if res.Events != 3 {
		t.Errorf("verified %d events, expected 3", res.Events)
	}
	if len(res.Keys) != 1 {
		t.Errorf("ended with %d keys in force, expected 1", len(res.Keys))
	}
}

// The hole this closes. An interaction event carries no keys of its own, so the
// previous validator never checked its signature at all — and an interaction is
// what anchors a delegation approval. Anyone could fabricate one.
func TestAForgedInteractionIsRefused(t *testing.T) {
	f := loadSignedKEL(t)
	if _, err := ValidateSignedKEL(f["forged_ixn"]); err == nil {
		t.Fatal("an interaction signed by a key the identity never established was " +
			"accepted; anything it anchors — a delegation approval, a credential — " +
			"would be trusted on a forgery")
	}
}

func TestAnUnsignedInteractionIsRefused(t *testing.T) {
	f := loadSignedKEL(t)
	if _, err := ValidateSignedKEL(f["unsigned_ixn"]); err == nil {
		t.Fatal("an interaction with no signature at all was accepted")
	}
}

// A rotation must be signed by the keys it establishes — those are the
// pre-committed ones. Signing with the key being rotated away from would let a
// compromised old key keep authority, which is the exact thing pre-rotation
// exists to prevent.
func TestARotationSignedByTheSupersededKeyIsRefused(t *testing.T) {
	f := loadSignedKEL(t)
	if _, err := ValidateSignedKEL(f["rot_signed_by_old_key"]); err == nil {
		t.Fatal("a rotation signed by the key it was rotating away from was accepted")
	}
}

// The verdict must not be reachable without checking anything.
func TestAnEmptyLogIsNotAVerdict(t *testing.T) {
	if _, err := ValidateSignedKEL(nil); err == nil {
		t.Fatal("an empty log was accepted as a verified identity")
	}
}

// The two checks compose: a delegation approved by a seal inside a forged
// interaction must not be accepted, however well-formed the seal is.
func TestADelegationAnchoredInAForgedInteractionIsRefused(t *testing.T) {
	f := loadSignedKEL(t)
	b, err := os.ReadFile(filepath.Join("vectors", "signed_kel_fixture.json"))
	if err != nil {
		t.Skip("fixture not present")
	}
	var meta struct {
		Delegate string `json:"delegate"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	// The delegated event the forged interaction claims to approve.
	dipRaw, err := os.ReadFile(filepath.Join("vectors", "delegation_authority_fixture.json"))
	if err != nil {
		t.Skip("delegation fixture not present")
	}
	var df struct {
		DIP string `json:"dip"`
	}
	if err := json.Unmarshal(dipRaw, &df); err != nil {
		t.Fatal(err)
	}
	dip, err := base64.StdEncoding.DecodeString(df.DIP)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDelegationSigned(dip, f["forged_ixn"]); err == nil {
		t.Fatal("a delegation was authorised by a seal sitting in an interaction the " +
			"delegator never signed")
	}
}
