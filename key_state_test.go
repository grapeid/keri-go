package keri

import (
	"encoding/json"
	"testing"
)

// history builds a signed log for tests: a founding, then events added by the
// methods below, each signed by the keys in force.
type history struct {
	t        *testing.T
	k        *Keychain
	prefix   string
	messages [][]byte
	saids    []string
}

func newHistory(t *testing.T) *history {
	t.Helper()
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
	h := &history{t: t, k: k}
	ev := h.add(icp, k.Signers()...)
	h.prefix = ev.Identifier
	return h
}

func (h *history) add(raw []byte, signers ...Signer) *Event {
	h.t.Helper()
	signed, err := SignEvent(raw, signers...)
	if err != nil {
		h.t.Fatal(err)
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		h.t.Fatal(err)
	}
	h.messages = append(h.messages, signed.Message)
	h.saids = append(h.saids, ev.SAID)
	return ev
}

// interaction builds, signs and returns an interaction following the event at
// sn-1, without adding it.
func (h *history) interaction(sn int, seal string) []byte {
	h.t.Helper()
	raw, err := BuildInteraction(InteractionInput{Prefix: h.prefix,
		PriorSAID: h.saids[sn-1], SN: sn, Data: []json.RawMessage{json.RawMessage(seal)}})
	if err != nil {
		h.t.Fatal(err)
	}
	return h.sign(raw)
}

func (h *history) sign(raw []byte, signers ...Signer) []byte {
	h.t.Helper()
	if len(signers) == 0 {
		signers = h.k.Signers()
	}
	signed, err := SignEvent(raw, signers...)
	if err != nil {
		h.t.Fatal(err)
	}
	return signed.Message
}

func (h *history) addInteraction(seal string) {
	h.t.Helper()
	sn := len(h.messages)
	msg := h.interaction(sn, seal)
	h.messages = append(h.messages, msg)
	ev, _ := ParseEvent(msg[:mustEventLength(h.t, msg)])
	h.saids = append(h.saids, ev.SAID)
}

// rotation rotates the keychain and returns a rotation at sn following the
// event at sn-1, signed by the keys it reveals, without adding it.
func (h *history) rotation(sn int) []byte {
	h.t.Helper()
	keys, next, err := h.k.Rotate()
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := BuildRotation(RotationInput{Prefix: h.prefix, Keys: keys,
		PriorSAID: h.saids[sn-1], SN: sn, NextDigests: next})
	if err != nil {
		h.t.Fatal(err)
	}
	return h.sign(raw)
}

func mustEventLength(t *testing.T, msg []byte) int {
	t.Helper()
	raw, _, err := splitStream(msg)
	if err != nil {
		t.Fatal(err)
	}
	return len(raw)
}

func (h *history) verified() *SignedKELResult {
	h.t.Helper()
	r, err := ValidateSignedKEL(h.messages)
	if err != nil {
		h.t.Fatalf("the test's own log does not verify: %v", err)
	}
	return r
}

func faultKind(t *testing.T, err error, kind FaultKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; expected a %s refusal", kind)
	}
	ve, ok := err.(*ValidationError)
	if !ok || !ve.Has(kind) {
		t.Fatalf("refused with %v; expected a %s fault", err, kind)
	}
}

// One event verified against the state before it agrees with the whole log
// verified at once, at every point of a log that rotates and interacts.
func TestOneEventAtATimeAgreesWithTheWholeLog(t *testing.T) {
	h := newHistory(t)
	h.addInteraction(`{"i":"EA","s":"0","d":"EA"}`)
	h.messages = append(h.messages, h.rotation(2))
	h.saids = append(h.saids, mustSAID(t, h.messages[2]))
	h.addInteraction(`{"i":"EB","s":"0","d":"EB"}`)
	h.messages = append(h.messages, h.rotation(4))
	h.saids = append(h.saids, mustSAID(t, h.messages[4]))
	whole := h.verified()

	var state *KeyState
	for i, msg := range h.messages {
		v, err := VerifyEvent(state, msg)
		if err != nil {
			t.Fatalf("event %d verified on its own was refused: %v", i, err)
		}
		state = v.State
		at := whole.StateAt(uint64(i))
		if state.Digest() != at.Digest() || state.SN() != at.SN() ||
			!equalStrings(state.Keys(), at.Keys()) ||
			!equalStrings(state.NextDigests(), at.NextDigests()) ||
			state.LastEstablishment() != at.LastEstablishment() {
			t.Fatalf("after event %d the two disagree on the key state", i)
		}
	}
	if whole.State().Digest() != h.saids[len(h.saids)-1] {
		t.Error("State is not the state after the last event")
	}
	if whole.StateAt(uint64(len(h.messages))) != nil {
		t.Error("StateAt answers for a place past the end of the log")
	}
}

func mustSAID(t *testing.T, msg []byte) string {
	t.Helper()
	ev, err := ParseEvent(msg[:mustEventLength(t, msg)])
	if err != nil {
		t.Fatal(err)
	}
	return ev.SAID
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// What the whole log refuses at its end, the single event refuses after the
// state before it.
func TestOneEventIsRefusedWhereTheWholeLogWouldBe(t *testing.T) {
	h := newHistory(t)
	h.addInteraction(`{"i":"EA","s":"0","d":"EA"}`)
	r := h.verified()

	stranger, err := NewKeychain(NewMemoryKeyStore(), "stranger", 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildInteraction(InteractionInput{Prefix: h.prefix,
		PriorSAID: h.saids[1], SN: 2, Data: []json.RawMessage{json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	forged := h.sign(raw, stranger.Signers()...)
	_, err = VerifyEvent(r.State(), forged)
	faultKind(t, err, FaultThresholdNotMet)
	if _, whole := ValidateSignedKEL(append(h.messages, forged)); whole == nil {
		t.Fatal("the whole log accepted the forged interaction")
	}

	// An interaction at the next place that digests the wrong predecessor.
	raw, err = BuildInteraction(InteractionInput{Prefix: h.prefix,
		PriorSAID: h.saids[0], SN: 2, Data: []json.RawMessage{json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyEvent(r.State(), h.sign(raw))
	faultKind(t, err, FaultPriorDigestMismatch)

	// One at a place that does not follow.
	_, err = VerifyEvent(r.State(), h.interaction(1, `{"i":"EC","s":"0","d":"EC"}`))
	faultKind(t, err, FaultSequenceSkip)

	// A second founding.
	_, err = VerifyEvent(r.State(), h.messages[0])
	faultKind(t, err, FaultMalformed)

	// A rotation signed by a key nobody committed to.
	keys, err := stranger.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	next, err := stranger.NextDigests()
	if err != nil {
		t.Fatal(err)
	}
	rot, err := BuildRotation(RotationInput{Prefix: h.prefix, Keys: keys,
		PriorSAID: h.saids[1], SN: 2, NextDigests: next})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyEvent(r.State(), h.sign(rot, stranger.Signers()...))
	faultKind(t, err, FaultKeyNotPrecommitted)
}

// A founding is verified against no state at all.
func TestAFoundingIsVerifiedAgainstNoState(t *testing.T) {
	h := newHistory(t)
	v, err := VerifyEvent(nil, h.messages[0])
	if err != nil {
		t.Fatalf("a founding was refused: %v", err)
	}
	if v.State.Identifier() != h.prefix || v.State.SN() != 0 {
		t.Fatal("the founding's state names the wrong identity or place")
	}
	if _, err := VerifyEvent(nil, h.interaction(1, `{}`)); err == nil {
		t.Fatal("an interaction was accepted as a founding")
	}
}

func TestAdmitExtendsTheLog(t *testing.T) {
	h := newHistory(t)
	r := h.verified()
	a, err := r.Admit(h.interaction(1, `{"i":"EA","s":"0","d":"EA"}`))
	if err != nil {
		t.Fatalf("the next interaction was refused: %v", err)
	}
	if a.Repeat || a.Supersedes != 0 || a.State.SN() != 1 {
		t.Fatalf("extending the log was reported as repeat=%v supersedes=%d sn=%d",
			a.Repeat, a.Supersedes, a.State.SN())
	}
}

// The same event again is a repeat, not duplicity, and its attachments are
// still judged.
func TestAdmitTakesTheSameEventAgain(t *testing.T) {
	h := newHistory(t)
	h.addInteraction(`{"i":"EA","s":"0","d":"EA"}`)
	h.addInteraction(`{"i":"EB","s":"0","d":"EB"}`)
	r := h.verified()
	a, err := r.Admit(h.messages[1])
	if err != nil {
		t.Fatalf("an event the log holds was refused: %v", err)
	}
	if !a.Repeat || a.Supersedes != 0 {
		t.Fatalf("a repeat was reported as repeat=%v supersedes=%d", a.Repeat, a.Supersedes)
	}
	unsigned := h.messages[1][:mustEventLength(t, h.messages[1])]
	if _, err := r.Admit(unsigned); err == nil {
		t.Fatal("a held event arriving with no signature was admitted")
	}
}

// A recovery rotation after the first of three interactions replaces the last
// two, and opens the founding's commitment although its predecessor is an
// interaction.
func TestARecoveryRotationReplacesTheInteractionsAfterIt(t *testing.T) {
	h := newHistory(t)
	h.addInteraction(`{"i":"EA","s":"0","d":"EA"}`)
	h.addInteraction(`{"i":"EB","s":"0","d":"EB"}`)
	h.addInteraction(`{"i":"EC","s":"0","d":"EC"}`)
	r := h.verified()

	a, err := r.Admit(h.rotation(2))
	if err != nil {
		t.Fatalf("a recovery rotation after a kept interaction was refused: %v", err)
	}
	if a.Supersedes != 2 || a.Repeat {
		t.Fatalf("the recovery rotation replaces %d events; expected 2", a.Supersedes)
	}
	if a.State.LastEstablishment() != 2 || a.State.SN() != 2 {
		t.Fatal("the recovery rotation's state is not at its own place")
	}
}

// A rotation at a place a rotation holds is refused: the first establishment
// event seen there stands. So is an interaction at a taken place.
func TestTheFirstEstablishmentEventAtAPlaceStands(t *testing.T) {
	h := newHistory(t)
	first := h.rotation(1)
	h.messages = append(h.messages, first)
	h.saids = append(h.saids, mustSAID(t, first))
	h.addInteraction(`{"i":"EA","s":"0","d":"EA"}`)
	r := h.verified()

	// A different rotation at sn 1, signed by the same revealed key: valid on
	// its own, and it would replace an establishment event.
	keys, err := h.k.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewKeychain(NewMemoryKeyStore(), "other", 1)
	if err != nil {
		t.Fatal(err)
	}
	otherNext, err := other.NextDigests()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildRotation(RotationInput{Prefix: h.prefix, Keys: keys,
		PriorSAID: h.saids[0], SN: 1, NextDigests: otherNext})
	if err != nil {
		t.Fatal(err)
	}
	second := h.sign(raw)
	if _, err := VerifyEvent(r.StateAt(0), second); err != nil {
		t.Fatalf("the test's second rotation is not valid on its own: %v", err)
	}
	_, err = r.Admit(second)
	faultKind(t, err, FaultPlaceTaken)

	// A rotation at sn 2 replacing the interaction after the first rotation is
	// a recovery and is admitted.
	if _, err := r.Admit(h.rotation(2)); err != nil {
		t.Fatalf("a recovery rotation after an establishment event was refused: %v", err)
	}

	// An interaction at a taken place.
	_, err = r.Admit(h.interaction(2, `{"i":"EZ","s":"0","d":"EZ"}`))
	faultKind(t, err, FaultPlaceTaken)
}

// An event whose predecessor has not arrived cannot be judged.
func TestAdmitRefusesAnEventPastTheEnd(t *testing.T) {
	h := newHistory(t)
	h.addInteraction(`{"i":"EA","s":"0","d":"EA"}`)
	r, err := ValidateSignedKEL(h.messages[:1])
	if err != nil {
		t.Fatal(err)
	}
	h.addInteraction(`{"i":"EB","s":"0","d":"EB"}`)
	_, err = r.Admit(h.messages[2])
	faultKind(t, err, FaultSequenceSkip)
}

// A delegated identity rotates only by a delegated rotation, as keripy 1.3.6
// holds it: a plain rotation would take it over, or replace its interactions,
// without its delegator's approval.
func TestADelegatedIdentityIsNotRotatedByAPlainRotation(t *testing.T) {
	a, e := newRotKey(t, 'a'), newRotKey(t, 'e')
	dip, err := BuildDelegatedInception(DelegationInput{Delegator: testDelegator,
		Keys: pubsOf(a), NextDigests: digestsOf(e)})
	if err != nil {
		t.Fatal(err)
	}
	dipEv, err := ParseEvent(dip)
	if err != nil {
		t.Fatal(err)
	}
	dipMsg := handMessage(t, dip, placedSig{key: a, code: "A", index: 0})
	ixn, err := BuildInteraction(InteractionInput{Prefix: dipEv.Identifier,
		PriorSAID: dipEv.SAID, SN: 1, Data: []json.RawMessage{json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	ixnMsg := handMessage(t, ixn, placedSig{key: a, code: "A", index: 0})
	r, err := ValidateSignedKEL([][]byte{dipMsg, ixnMsg})
	if err != nil {
		t.Fatal(err)
	}
	if !r.State().Delegated() {
		t.Fatal("a delegated identity's state does not say it is delegated")
	}

	rot, err := BuildRotation(RotationInput{Prefix: dipEv.Identifier, Keys: pubsOf(e),
		PriorSAID: dipEv.SAID, SN: 1, NextDigests: digestsOf(a)})
	if err != nil {
		t.Fatal(err)
	}
	rotMsg := handMessage(t, rot, placedSig{key: e, code: "A", index: 0})
	_, err = r.Admit(rotMsg)
	faultKind(t, err, FaultMalformed)
	_, err = VerifyEvent(r.StateAt(0), rotMsg)
	faultKind(t, err, FaultMalformed)
	if _, err := ValidateSignedKEL([][]byte{dipMsg, rotMsg}); err == nil {
		t.Fatal("the whole log accepted a plain rotation of a delegated identity")
	}
}

// A repeat carrying only a witness's signature is admitted, so late witness
// signatures can be kept; one carrying nothing that verifies is refused.
func TestARepeatCarryingOnlyAWitnessSignatureIsAdmitted(t *testing.T) {
	a, e, w1, w2 := newRotKey(t, 'a'), newRotKey(t, 'e'), newWitness(t, 1), newWitness(t, 2)
	icp, msg, _ := witnessedInception(t, a, digestsOf(e), []rotKey{w1, w2}, 2)
	r := witnessingOf(t, msg)

	late := withWitnessSigs(t, icp, icp, placedSig{key: w1, code: "A", index: 0})
	adm, err := r.Admit(late)
	if err != nil {
		t.Fatalf("a repeat carrying a witness signature was refused: %v", err)
	}
	if !adm.Repeat || len(adm.Witnessing.Signed) != 1 || len(adm.Signatures) != 0 {
		t.Fatalf("the repeat reported repeat=%v witnesses=%v controller=%v",
			adm.Repeat, adm.Witnessing.Signed, adm.Signatures)
	}
	if adm.Log != r {
		t.Error("a repeat changed the log")
	}

	stranger := newWitness(t, 9)
	junk := withWitnessSigs(t, icp, icp, placedSig{key: stranger, code: "A", index: 0})
	_, err = r.Admit(junk)
	faultKind(t, err, FaultThresholdNotMet)
}

// Admission.Log is the log with the event admitted, so the next event is
// admitted to it without verifying the whole log again.
func TestEachAdmissionIsAdmittedToTheLogBefore(t *testing.T) {
	h := newHistory(t)
	r := h.verified()
	for sn := 1; sn <= 3; sn++ {
		msg := h.interaction(sn, `{"i":"EA","s":"0","d":"EA"}`)
		adm, err := r.Admit(msg)
		if err != nil {
			t.Fatalf("interaction %d was refused: %v", sn, err)
		}
		h.messages = append(h.messages, msg)
		h.saids = append(h.saids, mustSAID(t, msg))
		r = adm.Log
	}
	adm, err := r.Admit(h.rotation(2))
	if err != nil {
		t.Fatalf("a recovery rotation was refused: %v", err)
	}
	if adm.Supersedes != 2 || adm.Log.Events != 3 || adm.Log.State().Ilk() != "rot" ||
		len(adm.Log.Witnessing) != 3 {
		t.Fatalf("after recovery the log holds %d events ending in a %s",
			adm.Log.Events, adm.Log.State().Ilk())
	}
	if len(adm.Signatures) != 1 {
		t.Fatalf("the rotation reports %d verified signatures", len(adm.Signatures))
	}
	if r.Events != 4 {
		t.Error("admitting to a log changed the log it was admitted to")
	}
}

// Rewriting a result's Keys does not change what it verifies against.
func TestAResultsKeysAreACopy(t *testing.T) {
	h := newHistory(t)
	r := h.verified()
	stranger, err := NewKeychain(NewMemoryKeyStore(), "stranger", 1)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := stranger.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	r.Keys[0] = keys[0]
	raw, err := BuildInteraction(InteractionInput{Prefix: h.prefix,
		PriorSAID: h.saids[0], SN: 1, Data: []json.RawMessage{json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Admit(h.sign(raw, stranger.Signers()...))
	faultKind(t, err, FaultThresholdNotMet)
}
