package keri

import (
	"strings"
	"testing"
)

// The property everything else rests on: the key a rotation reveals is the key
// the previous event committed to.
//
// If this does not hold, pre-rotation is decoration — the rotation reveals a key
// nothing predicted and no validator accepts it.
func TestARotationRevealsExactlyTheKeyThatWasCommittedTo(t *testing.T) {
	k, err := NewKeychain(NewMemoryKeyStore(), "identity", 1)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := k.NextDigests()
	if err != nil {
		t.Fatal(err)
	}

	revealed, newCommitments, err := k.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if len(revealed) != 1 {
		t.Fatalf("rotation revealed %d keys, expected 1", len(revealed))
	}
	digestOfRevealed, err := NextDigest(revealed[0])
	if err != nil {
		t.Fatal(err)
	}
	if digestOfRevealed != committed[0] {
		t.Fatalf("the rotation revealed a key digesting to %s, but the identity had "+
			"committed to %s — no validator would accept this rotation",
			digestOfRevealed, committed[0])
	}
	if newCommitments[0] == committed[0] {
		t.Error("the new commitment repeats the old one, so the next rotation would " +
			"reveal a key that is already public")
	}
}

// Failure mode: the next key is never generated ahead of time.
func TestAnIdentityIsRotatableFromTheMomentItExists(t *testing.T) {
	store := NewMemoryKeyStore()
	if _, err := NewKeychain(store, "identity", 1); err != nil {
		t.Fatal(err)
	}
	names := store.Names()
	if len(names) != 2 {
		t.Fatalf("a new identity should hold the keys in force AND their committed "+
			"successors; the store holds %d keys: %v", len(names), names)
	}
}

// Failure mode: the next key is leaked before the rotation that reveals it.
func TestTheKeychainDoesNotRevealTheNextKey(t *testing.T) {
	k, err := NewKeychain(NewMemoryKeyStore(), "identity", 1)
	if err != nil {
		t.Fatal(err)
	}
	digests, err := k.NextDigests()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range digests {
		if !strings.HasPrefix(d, CodeBlake3_256) {
			t.Errorf("the commitment %q is not a digest; if this is a key, pre-rotation "+
				"protects nothing", d)
		}
	}
	// Signers() must hand back only what is in force, never the successors.
	inForce, err := k.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range k.Signers() {
		pub, err := s.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, c := range inForce {
			if c == pub {
				found = true
			}
		}
		if !found {
			t.Error("a signer was handed out that is not one of the keys in force")
		}
	}
}

// Failure mode: the current key is reused as the next one.
func TestTheNextKeyIsNeverTheCurrentKey(t *testing.T) {
	k, err := NewKeychain(NewMemoryKeyStore(), "identity", 2)
	if err != nil {
		t.Fatal(err)
	}
	current, err := k.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	committed, err := k.NextDigests()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range current {
		d, err := NextDigest(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range committed {
			if d == want {
				t.Fatal("the identity committed to a key it is already using, so a " +
					"rotation would reveal nothing an attacker does not already have")
			}
		}
	}
}

// Failure mode: the next key is lost. That is unrecoverable, and the code must
// say so rather than quietly substituting a fresh key nothing committed to.
func TestALostSuccessorIsReportedRatherThanReplaced(t *testing.T) {
	store := NewMemoryKeyStore()
	if _, err := NewKeychain(store, "identity", 1); err != nil {
		t.Fatal(err)
	}
	// A store that has the keys in force but not their successors — the shape
	// of a backup taken without them, or a process that generated them only in
	// memory.
	partial := NewMemoryKeyStore()
	inForce, err := store.Signer("identity/0/0")
	if err != nil {
		t.Fatal(err)
	}
	partial.signers["identity/0/0"] = inForce

	_, err = LoadKeychain(partial, "identity", 1, 0)
	if err == nil {
		t.Fatal("a keychain missing its committed successor loaded successfully; the " +
			"identity would appear healthy and be unable to ever rotate")
	}
	if !strings.Contains(err.Error(), "never rotate again") {
		t.Errorf("the failure does not explain that this is unrecoverable: %v", err)
	}
}

// A store must never overwrite a key an identity may have committed to.
func TestAStoreRefusesToReplaceAnExistingKey(t *testing.T) {
	store := NewMemoryKeyStore()
	if _, err := store.Generate("identity/0/0", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Generate("identity/0/0", true); err == nil {
		t.Fatal("a key was silently replaced; whatever the identity committed to is now " +
			"unrecoverable")
	}
}

// A keychain reloaded from a store must be the same keychain.
func TestAKeychainSurvivesAReload(t *testing.T) {
	store := NewMemoryKeyStore()
	k, err := NewKeychain(store, "identity", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	wantKeys, _ := k.CurrentKeys()
	wantNext, _ := k.NextDigests()

	reloaded, err := LoadKeychain(store, "identity", 1, k.Generation())
	if err != nil {
		t.Fatal(err)
	}
	gotKeys, _ := reloaded.CurrentKeys()
	gotNext, _ := reloaded.NextDigests()
	if gotKeys[0] != wantKeys[0] {
		t.Errorf("reloaded with %s in force, expected %s", gotKeys[0], wantKeys[0])
	}
	if gotNext[0] != wantNext[0] {
		t.Errorf("reloaded committed to %s, expected %s", gotNext[0], wantNext[0])
	}
}

// The whole cycle, checked by this package's own validator: incept, rotate,
// and confirm the log holds together with signatures verified against the key
// state it establishes.
func TestAnInceptionAndRotationFormAValidSignedLog(t *testing.T) {
	k, err := NewKeychain(NewMemoryKeyStore(), "identity", 1)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := k.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	next, err := k.NextDigests()
	if err != nil {
		t.Fatal(err)
	}
	icp, err := BuildInception(InceptionInput{Keys: keys, NextDigests: next})
	if err != nil {
		t.Fatal(err)
	}
	signedICP, err := SignEvent(icp, k.Signers()...)
	if err != nil {
		t.Fatal(err)
	}
	icpEv, err := ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}

	rotKeys, rotNext, err := k.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	rot, err := BuildRotation(RotationInput{
		Prefix: icpEv.Identifier, Keys: rotKeys, PriorSAID: icpEv.SAID,
		SN: 1, NextDigests: rotNext,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Signed with the keys now in force — the ones the rotation revealed.
	signedROT, err := SignEvent(rot, k.Signers()...)
	if err != nil {
		t.Fatal(err)
	}

	res, err := ValidateSignedKEL([][]byte{signedICP.Message, signedROT.Message})
	if err != nil {
		t.Fatalf("a log this package built and signed does not validate: %v", err)
	}
	if res.Events != 2 {
		t.Errorf("validated %d events, expected 2", res.Events)
	}
	if res.Keys[0] != rotKeys[0] {
		t.Errorf("the log establishes %s, but the rotation put %s in force",
			res.Keys[0], rotKeys[0])
	}
}

// Rotating twice must keep working: the second rotation reveals what the first
// committed to.
func TestRotatingRepeatedlyKeepsTheCommitmentChainIntact(t *testing.T) {
	k, err := NewKeychain(NewMemoryKeyStore(), "identity", 1)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 4; round++ {
		committed, err := k.NextDigests()
		if err != nil {
			t.Fatal(err)
		}
		revealed, _, err := k.Rotate()
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		d, err := NextDigest(revealed[0])
		if err != nil {
			t.Fatal(err)
		}
		if d != committed[0] {
			t.Fatalf("round %d revealed a key that was not the one committed to", round)
		}
	}
	if k.Generation() != 4 {
		t.Errorf("after four rotations the generation is %d", k.Generation())
	}
}

func TestAKeychainRefusesNonsenseArguments(t *testing.T) {
	store := NewMemoryKeyStore()
	for _, tc := range []struct {
		name  string
		build func() error
	}{
		{"no store", func() error { _, err := NewKeychain(nil, "x", 1); return err }},
		{"no label", func() error { _, err := NewKeychain(store, "", 1); return err }},
		{"no keys", func() error { _, err := NewKeychain(store, "x", 0); return err }},
		{"negative generation", func() error {
			_, err := LoadKeychain(store, "x", 1, -1)
			return err
		}},
	} {
		if err := tc.build(); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}
