package keri

import (
	"encoding/json"
	"testing"
)

// Witness-indexed signatures (the -B group) name their witness by its place in
// the witness list in force for the event, and each witness counts once.
// Ed25519 is deterministic, so one witness's signature re-attached under a
// second code needs no key at all; counting it twice would let one witness meet
// a threshold of two. keripy 1.3.6 counts it twice (interop/keripy_builds.py
// carries that case as an expected divergence).

func newWitness(t *testing.T, tag byte) rotKey {
	t.Helper()
	s, err := NewSoftwareSigner(seed(tag), false)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return rotKey{signer: s, pub: pub}
}

// withWitnessSigs appends a -B group of hand-written witness signatures over
// event to a message.
func withWitnessSigs(t *testing.T, msg, event []byte, sigs ...placedSig) []byte {
	t.Helper()
	out := append([]byte{}, msg...)
	out = append(out, '-', 'B', b64Alphabet[len(sigs)/64], b64Alphabet[len(sigs)%64])
	for _, p := range sigs {
		out = append(out, handSig(t, event, p)...)
	}
	return out
}

// witnessedInception founds an identity on a, with the witnesses and toad
// given, signed by a.
func witnessedInception(t *testing.T, a rotKey, next []string, wits []rotKey, toad int) ([]byte, []byte, *Event) {
	t.Helper()
	raw, err := BuildInception(InceptionInput{
		Keys: pubsOf(a), NextDigests: next, Witnesses: pubsOf(wits...), Toad: intPtr(toad),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, handMessage(t, raw, placedSig{key: a, code: "A", index: 0}), ev
}

func witnessingOf(t *testing.T, log ...[]byte) *SignedKELResult {
	t.Helper()
	res, err := ValidateSignedKEL(log)
	if err != nil {
		t.Fatalf("the log was refused: %v", err)
	}
	return res
}

func TestTwoWitnessesMeetAThresholdOfTwo(t *testing.T) {
	a, e, w1, w2 := newRotKey(t, 'a'), newRotKey(t, 'e'), newWitness(t, 1), newWitness(t, 2)
	icp, msg, _ := witnessedInception(t, a, digestsOf(e), []rotKey{w1, w2}, 2)
	res := witnessingOf(t, withWitnessSigs(t, msg, icp,
		placedSig{key: w1, code: "A", index: 0},
		placedSig{key: w2, code: "A", index: 1}))

	w := res.Witnessing[0]
	if !w.Met || len(w.Signed) != 2 || w.Threshold != 2 || !res.FullyWitnessed() {
		t.Fatalf("two designated witnesses signing did not meet toad 2: %+v", w)
	}
}

// One witness's signature written as A0 and again as B0: the same 64 bytes
// under two codes. It is one witness, and does not meet toad 2.
func TestOneWitnessReEncodedDoesNotMeetAThresholdOfTwo(t *testing.T) {
	a, e, w1, w2 := newRotKey(t, 'a'), newRotKey(t, 'e'), newWitness(t, 1), newWitness(t, 2)
	icp, msg, _ := witnessedInception(t, a, digestsOf(e), []rotKey{w1, w2}, 2)
	res := witnessingOf(t, withWitnessSigs(t, msg, icp,
		placedSig{key: w1, code: "A", index: 0},
		placedSig{key: w1, code: "B", index: 0}))

	w := res.Witnessing[0]
	if w.Met || len(w.Signed) != 1 || w.Signed[0] != w1.pub || res.FullyWitnessed() {
		t.Fatalf("one witness re-encoded counted as more than one: %+v", w)
	}
}

// A witness signature that does not verify, or that names a place outside the
// witness list, attests nothing. It is dropped and the log is still judged.
func TestAWitnessSignatureThatDoesNotVerifyIsDropped(t *testing.T) {
	a, e, w1, w2 := newRotKey(t, 'a'), newRotKey(t, 'e'), newWitness(t, 1), newWitness(t, 2)
	icp, msg, _ := witnessedInception(t, a, digestsOf(e), []rotKey{w1, w2}, 2)
	res := witnessingOf(t, withWitnessSigs(t, msg, icp,
		placedSig{key: w1, code: "A", index: 0},
		placedSig{key: w1, code: "A", index: 1}, // w1's signature at w2's place
		placedSig{key: w2, code: "A", index: 5}))

	w := res.Witnessing[0]
	if w.Met || len(w.Signed) != 1 || w.Dropped != 2 {
		t.Fatalf("a witness signature that attests nothing was counted: %+v", w)
	}
}

// A rotation's witness signatures index into the list it ESTABLISHES, and an
// interaction after it is judged against the same list and threshold.
func TestWitnessSignaturesIndexTheListInForce(t *testing.T) {
	a, c, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'e')
	w1, w2, w3 := newWitness(t, 1), newWitness(t, 2), newWitness(t, 3)
	icp, icpMsg, icpEv := witnessedInception(t, a, digestsOf(c), []rotKey{w1, w2}, 1)
	icpMsg = withWitnessSigs(t, icpMsg, icp, placedSig{key: w1, code: "A", index: 0})

	rot, err := BuildRotation(RotationInput{
		Prefix: icpEv.Identifier, PriorSAID: icpEv.SAID, SN: 1,
		Keys: pubsOf(c), NextDigests: digestsOf(e),
		PriorWitnesses: pubsOf(w1, w2), Cuts: pubsOf(w1), Adds: pubsOf(w3), Toad: intPtr(2),
	})
	if err != nil {
		t.Fatal(err)
	}
	rotEv, err := ParseEvent(rot)
	if err != nil {
		t.Fatal(err)
	}
	// The list in force is now [w2, w3].
	rotMsg := withWitnessSigs(t, handMessage(t, rot, placedSig{key: c, code: "A", index: 0}),
		rot, placedSig{key: w2, code: "A", index: 0}, placedSig{key: w3, code: "A", index: 1})

	ixn, err := BuildInteraction(InteractionInput{
		Prefix: icpEv.Identifier, PriorSAID: rotEv.SAID, SN: 2, Data: []json.RawMessage{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ixnMsg := withWitnessSigs(t, handMessage(t, ixn, placedSig{key: c, code: "A", index: 0}),
		ixn, placedSig{key: w3, code: "A", index: 1})

	res := witnessingOf(t, icpMsg, rotMsg, ixnMsg)
	if !res.Witnessing[0].Met || !res.Witnessing[1].Met {
		t.Fatalf("the inception and rotation were witnessed enough: %+v", res.Witnessing)
	}
	ixnW := res.Witnessing[2]
	if ixnW.Met || ixnW.Threshold != 2 || len(ixnW.Signed) != 1 || ixnW.Signed[0] != w3.pub {
		t.Fatalf("the interaction was not judged against [w2, w3] and toad 2: %+v", ixnW)
	}
	if res.FullyWitnessed() {
		t.Fatalf("a log whose last event lacks a witness was reported fully witnessed")
	}
}

func TestAnUnwitnessedIdentityIsTriviallyWitnessed(t *testing.T) {
	a, e := newRotKey(t, 'a'), newRotKey(t, 'e')
	msg, _ := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(e), `"1"`)
	res := witnessingOf(t, msg)
	if !res.FullyWitnessed() || len(res.Witnessing) != 1 || res.Witnessing[0].Threshold != 0 {
		t.Fatalf("an identity with no witnesses was not fully witnessed: %+v", res.Witnessing)
	}
}
