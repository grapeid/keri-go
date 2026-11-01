package keri

import (
	"encoding/json"
	"testing"
)

// Two thresholds keripy 1.3.6 accepts that a stricter reading refused. Each
// was checked with keripy's own builders and Kevery (interop/keripy_builds.py).

// A weighted threshold may weigh fewer keys than the event lists. The keys
// beyond the last weight carry no weight, and a signature by one of them makes
// the threshold unmet, exactly as keripy's Tholder decides it.
func TestAWeightedThresholdMayWeighFewerKeysThanAreListed(t *testing.T) {
	a, b, c, e := newRotKey(t, 'a'), newRotKey(t, 'b'), newRotKey(t, 'c'), newRotKey(t, 'e')
	raw, err := BuildInception(InceptionInput{
		Keys: pubsOf(a, b, c), Isith: json.RawMessage(`["1/2","1/2"]`),
		NextDigests: digestsOf(e), Nsith: json.RawMessage(`"1"`),
	})
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	firstTwo := handMessage(t, raw,
		placedSig{key: a, code: "A", index: 0}, placedSig{key: b, code: "A", index: 1})
	if _, err := ValidateSignedKEL([][]byte{firstTwo}); err != nil {
		t.Fatalf("three keys under two weights, signed by the two weighted keys, was refused: %v", err)
	}
	all := handMessage(t, raw, placedSig{key: a, code: "A", index: 0},
		placedSig{key: b, code: "A", index: 1}, placedSig{key: c, code: "A", index: 2})
	_, err = ValidateSignedKEL([][]byte{all})
	wantRefusedFor(t, err, FaultThresholdNotMet, "a signature by a key the threshold does not weigh")
}

// A next threshold of zero abandons the identity at founding even with a
// commitment listed: no rotation can meet it, and the founding is valid.
func TestANextThresholdOfZeroOverACommitmentIsAccepted(t *testing.T) {
	a, e, n := newRotKey(t, 'a'), newRotKey(t, 'e'), newRotKey(t, 'n')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(e), `"0"`)
	if _, err := ValidateSignedKEL([][]byte{icp}); err != nil {
		t.Fatalf("a founding with nt 0 over one commitment was refused: %v", err)
	}
	rot := rotationOf(t, icpEv, 1, pubsOf(e), `"1"`, digestsOf(n), `"1"`)
	_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: e, code: "A", index: 0})})
	if err == nil {
		t.Fatal("a rotation of an identity whose next threshold is zero was accepted")
	}
}
