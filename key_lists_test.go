package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// One key listed twice is two votes for one key. The builders never emit such
// an event, so these tests make one the way a peer could: build an honest
// event, overwrite one entry with a copy of another of the same length, and
// recompute the event's identifier so nothing but the repeat is wrong.
//
// keripy 1.3.6 accepts both attacks below (the interop harness,
// interop/keripy_builds.py, carries them as expected divergences).

// substitute replaces every occurrence of from with to in an event, which must
// be the same length, and recomputes the event's own identifier.
func substitute(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	if len(from) != len(to) {
		t.Fatalf("a substitution must keep the event's length")
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(string(raw), from, to)
	// Blank the identifier wherever it appears: d, and i on a self-addressing
	// inception. A rotation's i is the identity's prefix, not its own digest.
	blank := strings.ReplaceAll(out, ev.SAID, strings.Repeat("#", len(ev.SAID)))
	said, err := Blake3SAID([]byte(blank))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.ReplaceAll(blank, strings.Repeat("#", len(ev.SAID)), said))
}

// Inception k=[a,a], kt=2, signed by a at both places. a alone meets a
// threshold that was meant to need two keys.
func TestAnInceptionListingOneKeyTwiceIsRefused(t *testing.T) {
	a, b, e := newRotKey(t, 'a'), newRotKey(t, 'b'), newRotKey(t, 'e')
	honest, err := BuildInception(InceptionInput{
		Keys: pubsOf(a, b), Isith: json.RawMessage(`"2"`),
		NextDigests: digestsOf(e), Nsith: json.RawMessage(`"1"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	icp := substitute(t, honest, b.pub, a.pub)
	msg := handMessage(t, icp,
		placedSig{key: a, code: "A", index: 0},
		placedSig{key: a, code: "A", index: 1})

	_, err = ValidateSignedKEL([][]byte{msg})
	wantRefusedFor(t, err, FaultKeyListInvalid, "an inception whose k names one key twice")
	wantRefusedFor(t, ValidateEvent(icp), FaultKeyListInvalid,
		"the same inception, judged as an event alone")
}

// Inception n=[H(c),H(c)], nt=2, then a rotation to k=[c] signed by c at both
// prior places. Whoever holds c alone takes the identity over.
func TestAnInceptionCommittingToOneKeyTwiceIsRefused(t *testing.T) {
	a, c, d, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'd'), newRotKey(t, 'e')
	honest, err := BuildInception(InceptionInput{
		Keys: pubsOf(a), Isith: json.RawMessage(`"1"`),
		NextDigests: digestsOf(c, d), Nsith: json.RawMessage(`"2"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	icp := substitute(t, honest, d.digest, c.digest)
	icpEv, err := ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	icpMsg := handMessage(t, icp, placedSig{key: a, code: "A", index: 0})
	rot := rotationOf(t, icpEv, 1, pubsOf(c), `"1"`, digestsOf(e), `"1"`)
	rotMsg := handMessage(t, rot,
		placedSig{key: c, code: "2A", index: 0, ondex: 0},
		placedSig{key: c, code: "2A", index: 0, ondex: 1})

	_, err = ValidateSignedKEL([][]byte{icpMsg, rotMsg})
	wantRefusedFor(t, err, FaultKeyListInvalid,
		"a log founded on a commitment that names one next key twice")
}

// A rotation is an establishment event too: its k and its n are held to the
// same rule.
func TestARotationListingOneKeyOrDigestTwiceIsRefused(t *testing.T) {
	a, c, d, e, f := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'd'),
		newRotKey(t, 'e'), newRotKey(t, 'f')
	_, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c, d), `"1"`)

	rot := rotationOf(t, icpEv, 1, pubsOf(c, d), `"1"`, digestsOf(e), `"1"`)
	wantRefusedFor(t, ValidateEvent(substitute(t, rot, d.pub, c.pub)), FaultKeyListInvalid,
		"a rotation whose k names one key twice")

	rot = rotationOf(t, icpEv, 1, pubsOf(c), `"1"`, digestsOf(e, f), `"1"`)
	wantRefusedFor(t, ValidateEvent(substitute(t, rot, f.digest, e.digest)), FaultKeyListInvalid,
		"a rotation whose n names one digest twice")
}

// The repeat is judged by the key, not by how it is written: one Ed25519 key
// under the transferable and the non-transferable code is still one key.
func TestOneKeyUnderTwoCodesIsOneKey(t *testing.T) {
	a := newRotKey(t, 'a')
	raw, err := MatterRaw(CodeEd25519, a.pub, 32)
	if err != nil {
		t.Fatal(err)
	}
	asB, err := MatterQB64(CodeEd25519N, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := noRepeatedKeysOrDigests([]string{a.pub, asB}, nil); err == nil {
		t.Fatalf("one key written under D and under B was taken for two keys")
	}
	b := newRotKey(t, 'b')
	if err := noRepeatedKeysOrDigests(pubsOf(a, b), digestsOf(a, b)); err != nil {
		t.Fatalf("two distinct keys and their digests were refused: %v", err)
	}
}

// Every builder that writes an establishment event refuses the repeat, through
// the same function the validator uses.
func TestNoBuilderEmitsARepeatedKeyOrDigest(t *testing.T) {
	a, c, e := newRotKey(t, 'a'), newRotKey(t, 'c'), newRotKey(t, 'e')
	_, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(c), `"1"`)
	delegator := icpEv.Identifier

	attempts := map[string]func() error{
		"inception k": func() error {
			_, err := BuildInception(InceptionInput{Keys: pubsOf(a, a),
				NextDigests: digestsOf(e)})
			return err
		},
		"inception n": func() error {
			_, err := BuildInception(InceptionInput{Keys: pubsOf(a),
				NextDigests: digestsOf(e, e)})
			return err
		},
		"rotation k": func() error {
			_, err := BuildRotation(RotationInput{Prefix: icpEv.Identifier,
				PriorSAID: icpEv.SAID, SN: 1, Keys: pubsOf(c, c), NextDigests: digestsOf(e)})
			return err
		},
		"rotation n": func() error {
			_, err := BuildRotation(RotationInput{Prefix: icpEv.Identifier,
				PriorSAID: icpEv.SAID, SN: 1, Keys: pubsOf(c), NextDigests: digestsOf(e, e)})
			return err
		},
		"delegated inception n": func() error {
			_, err := BuildDelegatedInception(DelegationInput{Delegator: delegator,
				Keys: pubsOf(a), NextDigests: digestsOf(e, e)})
			return err
		},
		"delegated rotation k": func() error {
			_, err := BuildDelegatedRotation(DelegationInput{Delegator: delegator,
				Prefix: icpEv.Identifier, PriorSAID: icpEv.SAID, SN: 1,
				Keys: pubsOf(c, c), NextDigests: digestsOf(e)})
			return err
		},
	}
	for name, build := range attempts {
		err := build()
		if err == nil || !strings.Contains(err.Error(), "listed twice") {
			t.Errorf("%s: a repeated entry was not refused as a repeat: %v", name, err)
		}
	}
}
