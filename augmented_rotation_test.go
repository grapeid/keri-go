package keri

import "testing"

// An augmented rotation lists a key the previous establishment event never
// committed to. KERI allows it and keripy 1.3.6 accepts it when the thresholds
// are met: the added key opens nothing, and its signature counts toward the
// new signing threshold only. A verifier that refused it would refuse logs the
// rest of the world accepts.

// Signed as keripy's own signer signs an augmented rotation, with the plain
// "A" code at every place, and with the added key signing current-only.
func TestAnAugmentedRotationIsAcceptedWhenTheThresholdsAreMet(t *testing.T) {
	a, c, z, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'z'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c), `"1"`)
	rot := rotationOf(t, icpEv, 1, pubsOf(c, z), `"2"`, digestsOf(e), `"1"`)

	for name, sigs := range map[string][]placedSig{
		"every place written as A": {
			{key: c, code: "A", index: 0}, {key: z, code: "A", index: 1}},
		"the added key current-only": {
			{key: c, code: "A", index: 0}, {key: z, code: "B", index: 1}},
	} {
		if err := ValidateKEL([][]byte{mustBody(t, icp), rot}); err != nil {
			t.Fatalf("%s: the augmented rotation was refused without signatures: %v", name, err)
		}
		if _, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot, sigs...)}); err != nil {
			t.Errorf("%s: an augmented rotation meeting both thresholds was refused: %v",
				name, err)
		}
	}
}

// The added key cannot authorise the rotation by itself: it opens no
// commitment, so the prior next threshold is unmet.
func TestAnAddedKeyAloneCannotAuthoriseARotation(t *testing.T) {
	a, c, z, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'z'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c), `"1"`)
	rot := rotationOf(t, icpEv, 1, pubsOf(c, z), `"1"`, digestsOf(e), `"1"`)

	_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: z, code: "A", index: 1})})
	wantRefusedFor(t, err, FaultThresholdNotMet, "an augmented rotation signed by the added key alone")

	// And a rotation listing only keys nobody committed to is refused without
	// its signatures being looked at.
	only := rotationOf(t, icpEv, 1, pubsOf(z), `"1"`, digestsOf(e), `"1"`)
	err = ValidateKEL([][]byte{mustBody(t, icp), only})
	wantRefusedFor(t, err, FaultKeyNotPrecommitted, "a rotation to keys never committed to")
}
