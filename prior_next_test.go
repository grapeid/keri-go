package keri

import (
	"encoding/json"
	"errors"
	"testing"
)

// A rotation is authorised by the prior commitments its SIGNING keys open, and
// those must meet the prior next threshold. Counting the keys a rotation merely
// lists is the mistake these tests exist to catch: a rotation could list every
// committed key, be signed by one, and pass a next threshold of all of them.
//
// Every expectation below was checked against keripy 1.3.6's Kevery, by the
// interop harness (interop/), which feeds the same shapes to the reference.

// rotKey is one key of a test identity.
type rotKey struct {
	signer Signer
	pub    string
	digest string
}

func newRotKey(t *testing.T, tag byte) rotKey {
	t.Helper()
	s, err := NewSoftwareSigner(seed(tag), true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := NextDigest(pub)
	if err != nil {
		t.Fatal(err)
	}
	return rotKey{signer: s, pub: pub, digest: d}
}

func pubsOf(keys ...rotKey) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.pub
	}
	return out
}

func digestsOf(keys ...rotKey) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.digest
	}
	return out
}

// placedSig is a signature written by hand at a stated place, so these tests
// do not depend on the writer they are checking: code "A" (one index for both
// lists), "B" (current list only) or "2A" (index and prior-next place apart).
type placedSig struct {
	key   rotKey
	code  string
	index int
	ondex int
}

func handSig(t *testing.T, event []byte, p placedSig) string {
	t.Helper()
	raw, err := p.key.signer.Sign(event)
	if err != nil {
		t.Fatal(err)
	}
	var code string
	switch p.code {
	case "A", "B":
		code = p.code + string(b64Alphabet[p.index])
	case "2A", "2B":
		code = p.code + string(b64Alphabet[p.index/64]) + string(b64Alphabet[p.index%64]) +
			string(b64Alphabet[p.ondex/64]) + string(b64Alphabet[p.ondex%64])
	default:
		t.Fatalf("no such code %q", p.code)
	}
	q, err := MatterQB64(code, raw)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// handMessage frames an event with hand-written signatures. The controller
// signature counter is written directly, so a signature of any width can be
// attached.
func handMessage(t *testing.T, event []byte, sigs ...placedSig) []byte {
	t.Helper()
	out := append([]byte{}, event...)
	out = append(out, '-', 'A', b64Alphabet[len(sigs)/64], b64Alphabet[len(sigs)%64])
	for _, p := range sigs {
		out = append(out, handSig(t, event, p)...)
	}
	return out
}

// foundedOn incepts an identity on keys, committing to nexts, signed by every
// key at its own place.
func foundedOn(t *testing.T, keys []rotKey, kt string, nexts []string, nt string) ([]byte, *Event) {
	t.Helper()
	raw, err := BuildInception(InceptionInput{
		Keys: pubsOf(keys...), Isith: json.RawMessage(kt),
		NextDigests: nexts, Nsith: json.RawMessage(nt),
	})
	if err != nil {
		t.Fatalf("building the inception: %v", err)
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make([]placedSig, len(keys))
	for i, k := range keys {
		sigs[i] = placedSig{key: k, code: "A", index: i}
	}
	return handMessage(t, raw, sigs...), ev
}

func rotationOf(t *testing.T, prior *Event, sn int, keys []string, kt string,
	nexts []string, nt string) []byte {
	t.Helper()
	raw, err := BuildRotation(RotationInput{
		Prefix: prior.Identifier, PriorSAID: prior.SAID, SN: sn,
		Keys: keys, Isith: json.RawMessage(kt),
		NextDigests: nexts, Nsith: json.RawMessage(nt),
	})
	if err != nil {
		t.Fatalf("building the rotation: %v", err)
	}
	return raw
}

func wantRefusedFor(t *testing.T, err error, kind FaultKind, why string) {
	t.Helper()
	if err == nil {
		t.Fatalf("ACCEPTED: %s", why)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || !ve.Has(kind) {
		t.Fatalf("refused, but not with %q (%s): %v", kind, why, err)
	}
}

// The defect: the prior next threshold was checked against the keys listed in
// k. Here both committed keys are listed, the new kt is one, and only one of
// them signs. keripy refuses it: one opened commitment does not meet nt = 2.
func TestARotationIsAuthorisedByTheKeysThatSignedNotTheKeysListed(t *testing.T) {
	a, c, d, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'd'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c, d), `"2"`)
	rot := rotationOf(t, icpEv, 1, pubsOf(c, d), `"1"`, digestsOf(e), `"1"`)

	_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c, code: "A", index: 0})})
	wantRefusedFor(t, err, FaultThresholdNotMet,
		"a rotation opening one of two commitments under a prior next threshold of two")

	if _, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c, code: "A", index: 0},
		placedSig{key: d, code: "A", index: 1})}); err != nil {
		t.Fatalf("the same rotation signed by both committed keys was refused: %v", err)
	}
}

// A current-only signature ("B") counts toward the new kt and opens nothing,
// so it cannot authorise a rotation on its own.
func TestACurrentOnlySignatureOpensNoCommitment(t *testing.T) {
	a, c, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c), `"1"`)
	rot := rotationOf(t, icpEv, 1, pubsOf(c), `"1"`, digestsOf(e), `"1"`)

	_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c, code: "B", index: 0})})
	wantRefusedFor(t, err, FaultThresholdNotMet,
		"a rotation whose only signature is current-only, which opens no commitment")

	if _, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot,
		placedSig{key: c, code: "A", index: 0})}); err != nil {
		t.Fatalf("the same rotation signed with a code that opens n[0] was refused: %v", err)
	}
}

// The prior commitment is the last ESTABLISHMENT event's, never an
// interaction's: an interaction between the inception and the rotation
// commits to nothing and changes nothing.
func TestARotationAfterAnInteractionOpensTheEstablishmentEventsCommitment(t *testing.T) {
	a, c, d, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'd'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c, d), `"2"`)
	ixn, err := BuildInteraction(InteractionInput{
		Prefix: icpEv.Identifier, PriorSAID: icpEv.SAID, SN: 1, Data: []json.RawMessage{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ixnEv, err := ParseEvent(ixn)
	if err != nil {
		t.Fatal(err)
	}
	rot := rotationOf(t, ixnEv, 2, pubsOf(c, d), `"1"`, digestsOf(e), `"1"`)
	ixnMsg := handMessage(t, ixn, placedSig{key: a, code: "A", index: 0})

	_, err = ValidateSignedKEL([][]byte{icp, ixnMsg, handMessage(t, rot,
		placedSig{key: c, code: "A", index: 0})})
	wantRefusedFor(t, err, FaultThresholdNotMet,
		"after an interaction, a rotation opening one of the inception's two commitments")
	if _, err := ValidateSignedKEL([][]byte{icp, ixnMsg, handMessage(t, rot,
		placedSig{key: c, code: "A", index: 0},
		placedSig{key: d, code: "A", index: 1})}); err != nil {
		t.Fatalf("after an interaction, a rotation opening both commitments was refused: %v", err)
	}
}

// Three owners, any two of whom must act, each with two keys: the nested
// weighted form of the threshold, exactly as keripy 1.3.6 serialises it. Here
// every committed key is revealed at its own place, so index and prior-next
// place agree and the plain "A" code carries both.
func TestANestedThresholdAuthorisesARotationOnlyWithTwoOwners(t *testing.T) {
	const nested = `[{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]}]`
	founders := []rotKey{newRotKey(t, 'f'), newRotKey(t, 'g'), newRotKey(t, 'h'),
		newRotKey(t, 'i'), newRotKey(t, 'j'), newRotKey(t, 'k')}
	next := []rotKey{newRotKey(t, 'l'), newRotKey(t, 'm'), newRotKey(t, 'n'),
		newRotKey(t, 'o'), newRotKey(t, 'p'), newRotKey(t, 'q')}
	after := newRotKey(t, 'r')

	icp, icpEv := foundedOn(t, founders, nested, digestsOf(next...), nested)
	rot := rotationOf(t, icpEv, 1, pubsOf(next...), nested, digestsOf(after), `"1"`)

	sigsAt := func(places ...int) []placedSig {
		out := make([]placedSig, len(places))
		for i, p := range places {
			out[i] = placedSig{key: next[p], code: "A", index: p}
		}
		return out
	}
	// Owners 0 and 2, both keys each.
	if _, err := ValidateSignedKEL([][]byte{icp,
		handMessage(t, rot, sigsAt(0, 1, 4, 5)...)}); err != nil {
		t.Fatalf("two owners acting with both their keys were refused: %v", err)
	}
	// Owner 0 alone, both keys.
	_, err := ValidateSignedKEL([][]byte{icp, handMessage(t, rot, sigsAt(0, 1)...)})
	wantRefusedFor(t, err, FaultThresholdNotMet, "one owner acting alone")
	// One key of each of three owners: no owner's set reaches one.
	_, err = ValidateSignedKEL([][]byte{icp, handMessage(t, rot, sigsAt(0, 2, 4)...)})
	wantRefusedFor(t, err, FaultThresholdNotMet, "one key from each owner")
}

// What a builder writes must be the bytes the reference writes, or the
// identifier differs. Each expected value is keripy 1.3.6's
// json.dumps(Tholder(sith=input).sith) for the input.
func TestThresholdsRenderAsTheReferenceWritesThem(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`[["1","1"],["1","1"]]`, `[["1","1"],["1","1"]]`},
		{`[["1/2","1/2"],["1/2","1/2"]]`, `[["1/2","1/2"],["1/2","1/2"]]`},
		{`[{"1/2":["1","1"]},{"1/2":["1","1"]},{"1/2":["1","1"]}]`,
			`[{"1/2":["1","1"]},{"1/2":["1","1"]},{"1/2":["1","1"]}]`},
		{`[{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]}]`,
			`[{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]}]`},
		{`[["2/4", "1/1"], [{"3/6": ["1", "0"]}, "1/2"]]`, `[["1/2","1"],[{"1/2":["1","0"]},"1/2"]]`},
		{`[["1/2","1/2","1/2"]]`, `["1/2","1/2","1/2"]`},
	} {
		th, err := parseThresholdValue(json.RawMessage(tc.in), 1)
		if err != nil {
			t.Errorf("%s was refused: %v", tc.in, err)
			continue
		}
		if string(th.value) != tc.want {
			t.Errorf("%s rendered as %s, keripy writes %s", tc.in, th.value, tc.want)
		}
	}
	// Thresholds the reference refuses, because they could never be met or
	// are not thresholds at all.
	for _, bad := range []string{
		`[{"1/2":["1/2"]},"1/2"]`, `[["1/2"],["1"]]`, `["3/2"]`, `[{"1":["1"],"1/2":["1"]}]`,
	} {
		if _, err := parseThresholdValue(json.RawMessage(bad), 1); err == nil {
			t.Errorf("%s was accepted; keripy refuses it", bad)
		}
	}
}
