package keri

import (
	"encoding/json"
	"testing"
)

// The dual-index signature forms. A key whose place in k differs from the
// place of the commitment it opens in the prior n signs with "2A", carrying
// both places; a current-only signature with a two-character index is "2B".
// Each case below was checked against keripy 1.3.6 by the interop harness.

// A partial rotation revealing the SECOND commitment alone: k = [c] opens
// n[1]. Written as 2A (index 0, prior place 1) it is authorised; written as A
// it names n[0], which c does not open.
func TestAKeyOpeningALaterCommitmentSignsWithBothPlaces(t *testing.T) {
	a, x, c, e := newRotKey(t, 'a'), newRotKey(t, 'x'), newRotKey(t, 'c'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(x, c), `"1"`)
	rot := rotationOf(t, icpEv, 1, pubsOf(c), `"1"`, digestsOf(e), `"1"`)

	if _, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c, code: "2A", index: 0, ondex: 1})}); err != nil {
		t.Fatalf("revealing n[1] at k[0] with a dual-index signature was refused: %v", err)
	}

	_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c, code: "A", index: 0})})
	wantRefusedFor(t, err, FaultThresholdNotMet,
		"a single-index signature names n[0], which this key does not open")

	// A wrong prior place, or one beyond the commitment, opens nothing.
	for _, ondex := range []int{0, 2, 70} {
		_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
			placedSig{key: c, code: "2A", index: 0, ondex: ondex})})
		wantRefusedFor(t, err, FaultThresholdNotMet, "a dual-index signature at the wrong prior place")
	}
}

// Two owners, each of whom must act, in the stage-one layout: owner i holds
// k[i] and commitments n[2i] (classical) and n[2i+1] (reserve). Owner 1's key
// sits at k[1] and opens n[2], so it needs the dual-index form.
func TestTwoOwnersRotateWithTheSecondOwnerOpeningADifferentPlace(t *testing.T) {
	const nt = `[["1","1"],["1","1"]]`
	own0, own1 := newRotKey(t, 'f'), newRotKey(t, 'g')
	c0, p0, c1, p1 := newRotKey(t, 'h'), newRotKey(t, 'i'), newRotKey(t, 'j'), newRotKey(t, 'k')
	n0, n1 := newRotKey(t, 'l'), newRotKey(t, 'm')
	r0, r1 := newRotKey(t, 'n'), newRotKey(t, 'o')

	icp, icpEv := foundedOn(t, []rotKey{own0, own1}, `"2"`, digestsOf(c0, p0, c1, p1), nt)
	rot := rotationOf(t, icpEv, 1, pubsOf(c0, c1), `"2"`, digestsOf(n0, r0, n1, r1), nt)

	if _, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c0, code: "A", index: 0},
		placedSig{key: c1, code: "2A", index: 1, ondex: 2})}); err != nil {
		t.Fatalf("both owners revealing their classical keys was refused: %v", err)
	}

	// Owner 1 writing a single index names n[1], owner 0's reserve: owner 1's
	// clause is then unmet.
	_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c0, code: "A", index: 0},
		placedSig{key: c1, code: "A", index: 1})})
	wantRefusedFor(t, err, FaultThresholdNotMet, "owner 1's signature opening owner 0's place")
}

// A current-only signature with the two-character form counts toward the
// signing threshold. An interaction is signed that way here.
func TestABigCurrentOnlySignatureCountsTowardTheSigningThreshold(t *testing.T) {
	a, b := newRotKey(t, 'a'), newRotKey(t, 'b')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(b), `"1"`)
	ixn, err := BuildInteraction(InteractionInput{
		Prefix: icpEv.Identifier, PriorSAID: icpEv.SAID, SN: 1, Data: []json.RawMessage{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSignedKEL([][]byte{icp, handMessage(t, ixn,
		placedSig{key: a, code: "2B", index: 0})}); err != nil {
		t.Fatalf("an interaction signed with a 2B signature was refused: %v", err)
	}

	// 2B carries no prior place; non-zero ondex characters are refused, as
	// the reference refuses them.
	msg := handMessage(t, ixn, placedSig{key: a, code: "2B", index: 0, ondex: 1})
	if _, err := ValidateSignedKEL([][]byte{icp, msg}); err == nil {
		t.Fatal("a current-only signature carrying a prior place was accepted")
	}
}

// A whole log carrying dual-index signatures must still be split at the right
// places when published as one stream: each signature's width comes from its
// own code.
func TestAPublishedLogWithDualIndexSignaturesSplitsCorrectly(t *testing.T) {
	a, x, c, e := newRotKey(t, 'a'), newRotKey(t, 'x'), newRotKey(t, 'c'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(x, c), `"1"`)
	rot := handMessage(t, rotationOf(t, icpEv, 1, pubsOf(c), `"1"`, digestsOf(e), `"1"`),
		placedSig{key: c, code: "2A", index: 0, ondex: 1})

	stream, err := ExportKEL([][]byte{icp, rot})
	if err != nil {
		t.Fatalf("a log with a dual-index signature could not be published: %v", err)
	}
	back, err := ParseKELStream(stream)
	if err != nil {
		t.Fatalf("the published log could not be read back: %v", err)
	}
	if len(back) != 2 || string(back[1]) != string(rot) {
		t.Fatalf("the published log split into %d messages, not the two it holds", len(back))
	}
}
