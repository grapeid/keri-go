package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// A forked history: one identity, two different events at the same position,
// both correctly signed. Neither log can reveal this on its own — that is the
// whole reason watching exists.
func forkedIdentity(t *testing.T) (first [][]byte, second [][]byte, chain *Keychain) {
	t.Helper()
	chain, err := NewKeychain(NewMemoryKeyStore(), "forker", 1)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := chain.CurrentKeys()
	next, _ := chain.NextDigests()
	icp, err := BuildInception(InceptionInput{Keys: keys, NextDigests: next})
	if err != nil {
		t.Fatal(err)
	}
	signedICP, err := SignEvent(icp, chain.Signers()...)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}

	// Two different interactions at sequence number one. Both are validly
	// signed by the key in force; they simply anchor different things.
	build := func(note string) []byte {
		ixn, err := BuildInteraction(InteractionInput{
			Prefix: ev.Identifier, PriorSAID: ev.SAID, SN: 1,
			Data: []json.RawMessage{json.RawMessage(`{"note":"` + note + `"}`)},
		})
		if err != nil {
			t.Fatal(err)
		}
		s, err := SignEvent(ixn, chain.Signers()...)
		if err != nil {
			t.Fatal(err)
		}
		return s.Message
	}
	return [][]byte{signedICP.Message, build("shown to alice")},
		[][]byte{signedICP.Message, build("shown to bob")},
		chain
}

func TestTwoHistoriesForOneIdentityAreNoticed(t *testing.T) {
	first, second, _ := forkedIdentity(t)

	// Each log is internally sound. That is what makes duplicity invisible to
	// every other check in this package.
	if _, err := ValidateSignedKEL(first); err != nil {
		t.Fatalf("the first log does not validate, so this tests nothing: %v", err)
	}
	if _, err := ValidateSignedKEL(second); err != nil {
		t.Fatalf("the second log does not validate, so this tests nothing: %v", err)
	}

	w := NewSignatureCheckingWatcher()
	dup, err := w.ObserveLog(first)
	if err != nil {
		t.Fatal(err)
	}
	if dup != nil {
		t.Fatalf("duplicity reported within a single consistent log: %v", dup)
	}

	dup, err = w.ObserveLog(second)
	if err != nil {
		t.Fatal(err)
	}
	if dup == nil {
		t.Fatal("an identity presented two different histories and nothing noticed; " +
			"both logs validate on their own, so this is the only thing that could")
	}
	if dup.SN != 1 {
		t.Errorf("the conflict is reported at sequence number %d, expected 1", dup.SN)
	}
	if dup.Seen == dup.Conflicting {
		t.Error("the two events reported as conflicting are the same event")
	}
	if len(dup.SeenRaw) == 0 || len(dup.ConflictingRaw) == 0 {
		t.Error("the evidence was not kept, so nobody told about this could check it")
	}
}

// The same event arriving twice is routine, not a fork.
func TestSeeingTheSameEventTwiceIsNotDuplicity(t *testing.T) {
	first, _, _ := forkedIdentity(t)
	w := NewSignatureCheckingWatcher()
	for round := 0; round < 3; round++ {
		dup, err := w.ObserveLog(first)
		if err != nil {
			t.Fatal(err)
		}
		if dup != nil {
			t.Fatalf("round %d reported duplicity for a repeat of the same log: %v", round, dup)
		}
	}
}

// The property that stops the alarm becoming a weapon. If an event that does
// not verify could raise duplicity, anyone able to send bytes could brand any
// identity as duplicitous.
func TestAnUnverifiedEventCannotManufactureDuplicity(t *testing.T) {
	first, second, _ := forkedIdentity(t)
	w := NewSignatureCheckingWatcher()
	if _, err := w.ObserveLog(first); err != nil {
		t.Fatal(err)
	}

	// The conflicting event, with its signature broken.
	forged := append([]byte(nil), second[1]...)
	if forged[len(forged)-3] == 'A' {
		forged[len(forged)-3] = 'B'
	} else {
		forged[len(forged)-3] = 'A'
	}

	dup, err := w.Observe(forged)
	if dup != nil {
		t.Fatal("an event with a broken signature raised duplicity; anyone could brand " +
			"any identity duplicitous by sending noise")
	}
	if err == nil {
		t.Fatal("an event with a broken signature was accepted silently")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("refused for an unclear reason: %v", err)
	}

	// And the honest conflicting event is still detected afterwards, so the
	// refusal above did not simply break the watcher.
	dup, err = w.Observe(second[1])
	if err != nil {
		t.Fatal(err)
	}
	if dup == nil {
		t.Error("after refusing a forgery the watcher no longer notices real duplicity")
	}
}

// Two different identities are not a conflict, however similar their logs.
func TestTwoIdentitiesAreNotDuplicity(t *testing.T) {
	w := NewSignatureCheckingWatcher()
	for _, label := range []string{"alice", "bob"} {
		chain, err := NewKeychain(NewMemoryKeyStore(), label, 1)
		if err != nil {
			t.Fatal(err)
		}
		keys, _ := chain.CurrentKeys()
		next, _ := chain.NextDigests()
		icp, err := BuildInception(InceptionInput{Keys: keys, NextDigests: next})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := SignEvent(icp, chain.Signers()...)
		if err != nil {
			t.Fatal(err)
		}
		dup, err := w.Observe(signed.Message)
		if err != nil {
			t.Fatal(err)
		}
		if dup != nil {
			t.Fatalf("%s was reported as conflicting with a different identity", label)
		}
	}
	if len(w.Known()) != 2 {
		t.Errorf("the watcher knows %d identities, expected 2", len(w.Known()))
	}
}

func TestTheWatcherReportsWhatItHasSeen(t *testing.T) {
	first, _, _ := forkedIdentity(t)
	w := NewSignatureCheckingWatcher()
	if _, ok := w.Height("nobody"); ok {
		t.Error("the watcher claims to know an identity it has never seen")
	}
	if _, err := w.ObserveLog(first); err != nil {
		t.Fatal(err)
	}
	ev, err := ParseEvent(mustBody(t, first[0]))
	if err != nil {
		t.Fatal(err)
	}
	height, ok := w.Height(ev.Identifier)
	if !ok {
		t.Fatal("the watcher does not know an identity it recorded")
	}
	if height != 1 {
		t.Errorf("the log reaches sequence number %d, the watcher says %d", 1, height)
	}
}

func TestObservingNothingIsRefused(t *testing.T) {
	w := NewSignatureCheckingWatcher()
	if _, err := w.Observe(nil); err == nil {
		t.Error("observing an empty message was accepted")
	}
	if _, err := w.Observe([]byte("not an event")); err == nil {
		t.Error("observing bytes that are not an event was accepted")
	}
}

func mustBody(t *testing.T, message []byte) []byte {
	t.Helper()
	raw, _, err := splitStream(message)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A watcher records a rotation as evidence only when the keys that signed it
// open enough of the prior commitment, as ValidateSignedKEL requires. Otherwise
// anyone could manufacture a "conflicting" rotation signed by keys of their own,
// or by one of several committed keys.
func TestAWatcherChecksARotationsPriorCommitment(t *testing.T) {
	a, c, d, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'd'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c, d), `"2"`)
	rot := rotationOf(t, icpEv, 1, pubsOf(c, d), `"1"`, digestsOf(e), `"1"`)
	oneSigner := handMessage(t, rot, placedSig{key: c, code: "A", index: 0})
	bothSign := handMessage(t, rot, placedSig{key: c, code: "A", index: 0},
		placedSig{key: d, code: "A", index: 1})

	// Seen without its inception, the prior commitment is unknown.
	w := NewSignatureCheckingWatcher()
	if _, err := w.Observe(bothSign); err == nil {
		t.Fatal("a rotation was recorded without the commitment it must open")
	}
	if _, err := w.Observe(icp); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Observe(oneSigner); err == nil {
		t.Fatal("a rotation opening one of two commitments under nt 2 was recorded as evidence")
	}
	if _, err := w.Observe(bothSign); err != nil {
		t.Fatalf("a rotation opening both commitments was refused: %v", err)
	}

	// A second rotation at the same place, by a key nobody committed to, is
	// not evidence of duplicity: it is checked against the inception's
	// commitment, not the first rotation's.
	z := newRotKey(t, 'z')
	forged := handMessage(t, rotationOf(t, icpEv, 1, pubsOf(z), `"1"`, digestsOf(e), `"1"`),
		placedSig{key: z, code: "A", index: 0})
	if dup, err := w.Observe(forged); err == nil || dup != nil {
		t.Fatalf("a rotation to an uncommitted key was recorded (duplicity %v, error %v)", dup, err)
	}
}
