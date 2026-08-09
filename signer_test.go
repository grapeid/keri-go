package keri

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func seed(tag byte) []byte { return bytes.Repeat([]byte{tag}, ed25519.SeedSize) }

// Key derivation must match the reference exactly.
//
// These values came from keripy, not from running this package and writing down
// what it said. A key encoded differently is a different identity: for a
// single-key identity the identifier IS the key, so an encoding that disagrees
// by one character produces an identity nobody else can find.
func TestKeyDerivationMatchesKeripy(t *testing.T) {
	for _, tc := range []struct {
		tag          byte
		transferable bool
		wantKey      string
		wantNext     string
	}{
		{'a', true, "DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd", "EBY6SvxoQtfwrnzwLXLAkNPM92G49kZHVCKu11rFSX0j"},
		{'a', false, "BK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd", "EOYZf2i3nZLyOiLaThM3zPpdjngFtWT-zIBNQLbBuRFM"},
		{'b', true, "DC3wQSXwAVr7R86FOu-HcglP-UmMFMsbnhKXPCkn2g-m", "EEXekUYwyf4Blv1U_WFML7YliBR9GJXfl3osKtIevKQN"},
		{'w', false, "BMhTrQ8M0rYZrqks7sT9VqJNZJnVhM55JX5Fz9gTm2Cn", "EO5a6yr4yVREqYs-uMinN12CATVq6-x_tYn7K-V93mrD"},
	} {
		s, err := NewSoftwareSigner(seed(tc.tag), tc.transferable)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.wantKey {
			t.Errorf("seed %q transferable=%v derived %s, keripy derives %s",
				tc.tag, tc.transferable, got, tc.wantKey)
		}
		next, err := NextDigest(got)
		if err != nil {
			t.Fatal(err)
		}
		if next != tc.wantNext {
			t.Errorf("pre-rotation digest of %s is %s, keripy computes %s",
				got, next, tc.wantNext)
		}
	}
}

// The transferable flag is not cosmetic: a non-transferable identifier IS its
// key and can never rotate, so the code carries a permanent property.
func TestTheTransferableCodeDistinguishesTheTwoKinds(t *testing.T) {
	tr, _ := NewSoftwareSigner(seed('a'), true)
	nt, _ := NewSoftwareSigner(seed('a'), false)
	a, _ := tr.PublicKey()
	b, _ := nt.PublicKey()
	if a == b {
		t.Fatal("a transferable and a non-transferable key encoded identically")
	}
	if !strings.HasPrefix(a, CodeEd25519) || !strings.HasPrefix(b, CodeEd25519N) {
		t.Errorf("wrong codes: transferable %q, non-transferable %q", a[:1], b[:1])
	}
	if a[1:] != b[1:] {
		t.Error("the same seed produced different key material under the two codes")
	}
}

// An indexed signature must match the reference byte for byte, because the
// index is what attributes it to a key.
func TestIndexedSignatureMatchesKeripy(t *testing.T) {
	for _, tc := range []struct {
		tag  byte
		want string
	}{
		{'a', "AAC88r79lIyZ7LKyJEiv7CrdW_gD-Nu8EKwTrXcYIWL4ZCKbRXpG--4X2CDiyFoqCmuN6uZ-vfF60liGoYwiQpUK"},
		{'b', "AABYpw9HCA2gSy1jI8IeOcdc2ZevsF8IzAsSSIU6W5KWatWXIK0DVIWa3FZPTiz7CawYEwqNdO3kXVtvmqS6EtYN"},
	} {
		s, err := NewSoftwareSigner(seed(tc.tag), true)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := s.Sign([]byte("hello keri"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := indexedSigQB64(raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("seed %q signed to\n got %s\nwant %s", tc.tag, got, tc.want)
		}
	}
}

func TestTheIndexIsWrittenIntoTheSignature(t *testing.T) {
	s, _ := NewSoftwareSigner(seed('a'), true)
	raw, _ := s.Sign([]byte("hello keri"))
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		q, err := indexedSigQB64(raw, i)
		if err != nil {
			t.Fatal(err)
		}
		if seen[q] {
			t.Fatalf("index %d produced a signature identical to an earlier index", i)
		}
		seen[q] = true
		if got := string(q[1]); got != string(b64Alphabet[i]) {
			t.Errorf("index %d wrote %q into the code", i, got)
		}
	}
	if _, err := indexedSigQB64(raw, 64); err == nil {
		t.Error("an index too wide for a single digit was accepted, which would " +
			"attribute the signature to the wrong key")
	}
}

// A signer paired with the wrong key must fail where it happens, not remotely.
func TestSigningWithAKeyTheEventDoesNotDeclareIsRefused(t *testing.T) {
	a, _ := NewSoftwareSigner(seed('a'), true)
	b, _ := NewSoftwareSigner(seed('b'), true)
	pubA, _ := a.PublicKey()
	pubB, _ := b.PublicKey()
	next, _ := NextDigest(pubB)
	icp, err := BuildInception(InceptionInput{Keys: []string{pubA}, NextDigests: []string{next}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEvent(icp, b); err == nil {
		t.Fatal("an event was signed by a key it does not declare, which would be " +
			"attributed to the wrong holder")
	}
	if _, err := SignEvent(icp, a); err != nil {
		t.Fatalf("the declared key was refused: %v", err)
	}
}

// An interaction declares no keys, and must still be signable — it is what
// anchors delegation approvals and credential issuances.
func TestAnInteractionCanBeSignedThoughItDeclaresNoKeys(t *testing.T) {
	a, _ := NewSoftwareSigner(seed('a'), true)
	pubA, _ := a.PublicKey()
	next, _ := NextDigest(pubA)
	icp, err := BuildInception(InceptionInput{Keys: []string{pubA}, NextDigests: []string{next}})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	ixn, err := BuildInteraction(InteractionInput{
		Prefix: ev.Identifier, PriorSAID: ev.SAID, SN: 1, Data: []json.RawMessage{},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEvent(ixn, a)
	if err != nil {
		t.Fatalf("an interaction could not be signed: %v", err)
	}
	if len(signed.Message) <= len(signed.Event) {
		t.Error("the signed message carries no attachment")
	}
}

func TestSigningRefusesTheDegenerateCases(t *testing.T) {
	a, _ := NewSoftwareSigner(seed('a'), true)
	if _, err := SignEvent(nil, a); err == nil {
		t.Error("signing no event was accepted")
	}
	if _, err := SignEvent([]byte(`{"not":"an event"}`), a); err == nil {
		t.Error("signing bytes that are not an event was accepted")
	}
	pubA, _ := a.PublicKey()
	next, _ := NextDigest(pubA)
	icp, _ := BuildInception(InceptionInput{Keys: []string{pubA}, NextDigests: []string{next}})
	if _, err := SignEvent(icp); err == nil {
		t.Error("an event with no signers was accepted, and attests to nothing")
	}
	if _, err := a.Sign(nil); err == nil {
		t.Error("signing an empty message was accepted; that signature is reusable anywhere")
	}
}

func TestASignerRefusesAMalformedSeed(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewSoftwareSigner(make([]byte, n), true); err == nil {
			t.Errorf("a %d-byte seed was accepted as an Ed25519 seed", n)
		}
	}
}

// A generated key must be usable end to end and must not repeat.
func TestGeneratedKeysAreUsableAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		s, err := GenerateSigner(true)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := s.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if seen[pub] {
			t.Fatal("two generated keys were identical, so the randomness is not random")
		}
		seen[pub] = true
		sig, err := s.Sign([]byte("attest"))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifySignature(pub, []byte("attest"), sig); err != nil {
			t.Errorf("a freshly generated key produced a signature that does not verify: %v", err)
		}
	}
}

func TestVerificationRejectsATamperedMessage(t *testing.T) {
	s, _ := NewSoftwareSigner(seed('a'), true)
	pub, _ := s.PublicKey()
	sig, _ := s.Sign([]byte("the original message"))
	if err := VerifySignature(pub, []byte("the modified message"), sig); err == nil {
		t.Error("a signature verified over bytes it was not made over")
	}
	other, _ := NewSoftwareSigner(seed('b'), true)
	otherPub, _ := other.PublicKey()
	if err := VerifySignature(otherPub, []byte("the original message"), sig); err == nil {
		t.Error("a signature verified under a key that did not produce it")
	}
}

// The private key must not be reachable through the interface.
func TestTheSignerInterfaceExposesNoPrivateKey(t *testing.T) {
	var s Signer = &SoftwareSigner{}
	if _, ok := s.(interface{ PrivateKey() ed25519.PrivateKey }); ok {
		t.Error("the Signer interface exposes a private key, which cannot be satisfied " +
			"by a key held in an enclave")
	}
}
