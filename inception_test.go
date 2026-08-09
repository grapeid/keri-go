package keri

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// The derivation cases.
//
// These assert a PROPERTY of an inception event rather than asking for bytes,
// so they carry an event in their input and the answers in their expectation.
// They exist because the two derivation styles are the one place where a
// working implementation can be confidently, silently wrong: everything still
// serialises, everything still verifies against itself, and only a peer
// discovers that the identity has the wrong name.

// icpEventFields is enough of an inception event to check it and to rebuild it.
//
// Decoded into a struct rather than a map because the seals and the thresholds
// have to come back out in the order they went in; a map would sort them and
// the rebuilt event would no longer be the event that was read.
type icpEventFields struct {
	T  string            `json:"t"`
	D  string            `json:"d"`
	I  string            `json:"i"`
	KT json.RawMessage   `json:"kt"`
	K  []string          `json:"k"`
	NT json.RawMessage   `json:"nt"`
	N  []string          `json:"n"`
	BT string            `json:"bt"`
	B  []string          `json:"b"`
	A  []json.RawMessage `json:"a"`
}

func TestInceptionDerivation(t *testing.T) {
	vf := loadForTest(t)
	checked := 0

	for _, c := range vf.Cases {
		if c.Kind != "property" {
			continue
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			var in struct {
				RawB64 string `json:"raw_b64"`
			}
			if err := json.Unmarshal(c.Input, &in); err != nil {
				t.Fatalf("case input is not readable: %v", err)
			}
			raw, err := base64.StdEncoding.DecodeString(in.RawB64)
			if err != nil {
				t.Fatalf("case input is not decodable: %v", err)
			}
			var ev icpEventFields
			if err := json.Unmarshal(raw, &ev); err != nil {
				t.Fatalf("case input is not a readable event: %v", err)
			}
			if ev.T != "icp" {
				t.Skipf("not an inception event (%q); this test only covers icp", ev.T)
			}

			// The SAID recomputed from the event's own bytes. Blanking the
			// fields in place rather than re-serialising is deliberate:
			// re-serialising would test this package's serialiser against
			// itself, whereas substituting placeholders of the same width
			// leaves every other byte exactly as the reference wrote it.
			//
			// WHICH fields get blanked depends on the derivation, and that is
			// the part worth stating. A single-key event blanks "d" alone,
			// because "i" already held the key when the digest was taken. A
			// multi-key event blanks "d" AND "i", because the digest is what
			// produced "i" and so cannot have had it as an input. Checking a
			// multi-key inception with the single-key procedure yields a digest
			// that matches nothing, which reads as a corrupt event rather than
			// as the wrong procedure.
			blanked := blankField(t, raw, "d", ev.D)
			if len(ev.K) > 1 {
				blanked = blankField(t, blanked, "i", ev.I)
			}
			said, err := Blake3SAID(blanked)
			if err != nil {
				t.Fatalf("could not digest the event: %v", err)
			}
			if c.Expect.SAID != "" && said != c.Expect.SAID {
				t.Errorf("the event digests to %q but the case expects %q\nwhy: %s",
					said, c.Expect.SAID, c.Why)
			}

			// The derivation rule itself. One key means the identifier IS the
			// key; more than one means it is the digest. An implementation that
			// collapses these two into "aid = said" passes every multi-key case
			// and breaks every single-key identity in existence.
			wantAID := said
			if len(ev.K) == 1 {
				wantAID = ev.K[0]
			}
			if wantAID != c.Expect.AID {
				t.Errorf("derivation gives the identifier %q but the case expects %q\nwhy: %s",
					wantAID, c.Expect.AID, c.Why)
			}
			if ev.I != c.Expect.AID {
				t.Errorf("the event's own identifier is %q but the case expects %q",
					ev.I, c.Expect.AID)
			}
			if len(ev.K) == 1 && ev.D == ev.I {
				t.Errorf("this single-key event has d == i, so it was built by digesting "+
					"rather than by basic derivation\nwhy: %s", c.Why)
			}

			// And the round trip: given only what the event says about itself,
			// this implementation must produce that event back, byte for byte.
			// Without this the case would only check arithmetic over bytes
			// somebody else wrote.
			got, err := BuildInception(inceptionInputFrom(t, ev))
			if err != nil {
				t.Fatalf("could not rebuild the event: %v", err)
			}
			if string(got) != string(raw) {
				t.Fatalf("rebuilding the event does not reproduce it.\nwhy: %s\n want: %q\n got:  %q",
					c.Why, string(raw), string(got))
			}
			checked++
		})
	}

	if checked == 0 {
		// An empty run would report success while asserting nothing, which is
		// the one outcome worse than a failure.
		t.Error("no derivation cases were checked, so this test proves nothing")
	}
}

// blankField replaces one field's value with placeholders of the same width,
// which is the state the digest was taken over.
//
// Same width because the version string has already declared the event's
// length: a placeholder of any other size describes a different event, and the
// digest would be of something that never existed.
func blankField(t *testing.T, raw []byte, field, value string) []byte {
	t.Helper()
	if value == "" {
		t.Fatalf("the event carries no %q to blank", field)
	}
	needle := `"` + field + `":"` + value + `"`
	if !strings.Contains(string(raw), needle) {
		t.Fatalf("could not find %s in the event", needle)
	}
	blank := `"` + field + `":"` + strings.Repeat("#", len(value)) + `"`
	return []byte(strings.Replace(string(raw), needle, blank, 1))
}

// inceptionInputFrom recovers the inputs an event was built from.
func inceptionInputFrom(t *testing.T, ev icpEventFields) InceptionInput {
	t.Helper()
	toad, err := strconv.ParseInt(ev.BT, 16, 64)
	if err != nil {
		t.Fatalf("the event's witness threshold %q is not a hex number: %v", ev.BT, err)
	}
	return InceptionInput{
		Keys:        ev.K,
		NextDigests: ev.N,
		Witnesses:   ev.B,
		Toad:        int(toad),
		Isith:       ev.KT,
		Nsith:       ev.NT,
		Data:        ev.A,
	}
}

// The vectors label each inception case with the derivation keripy used. This
// implementation does not read that label — it applies keripy's own rule, which
// is made from the key count — so the label is checked here instead.
//
// Without this, a future case whose label disagreed with the key count would
// pass silently on the bytes and leave the rule wrong for every case after it.
func TestTheDerivationLabelAgreesWithTheRule(t *testing.T) {
	vf := loadForTest(t)
	for _, c := range vf.Cases {
		if c.Kind != "inception" {
			continue
		}
		var in struct {
			Keys       []string `json:"keys"`
			Derivation string   `json:"derivation"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Errorf("%s: input is not readable: %v", c.ID, err)
			continue
		}
		if in.Derivation == "" {
			continue
		}
		want := "self-addressing"
		if len(in.Keys) == 1 {
			want = "basic"
		}
		if want != in.Derivation {
			t.Errorf("%s: the case is labelled %q derivation but has %d keys, which this "+
				"implementation derives as %q — one of the two is wrong and the bytes "+
				"alone would not say which",
				c.ID, in.Derivation, len(in.Keys), want)
		}
	}
}

// The parts of threshold formatting no vector reaches.
//
// The vectors exercise "1", "2", "3" and ["1/2","1/2","1/2"] and nothing else,
// so every other shape the reference accepts is unpinned by them. These pin the
// rules read out of keripy's Tholder, because each is a place where a threshold
// that MEANS the same thing would be WRITTEN differently — and a threshold
// written differently is a different identifier.
func TestThresholdFormatting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given string
		keys  int
		want  string
	}{
		{"a hex string is normalised", `"02"`, 3, `"2"`},
		{"ten is hex, not decimal", `"a"`, 10, `"a"`},
		{"a number is written as a string", `2`, 3, `"2"`},
		{"weights are reduced to lowest terms", `["2/4","2/4","2/4"]`, 3, `["1/2","1/2","1/2"]`},
		{"a whole weight loses its denominator", `["1/1","1/2","1/2"]`, 3, `["1","1/2","1/2"]`},
		{"whitespace is not part of the event", `["1/2", "1/2", "1/2"]`, 3, `["1/2","1/2","1/2"]`},
		{"a single clause is written flat", `[["1/2","1/2","1/2"]]`, 3, `["1/2","1/2","1/2"]`},
		{"several clauses stay nested", `[["1/2","1/2"],["1"]]`, 3, `[["1/2","1/2"],["1"]]`},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderThreshold(json.RawMessage(tc.given), tc.keys, 1, "kt")
			if err != nil {
				t.Fatalf("%s was refused: %v", tc.given, err)
			}
			if string(got) != tc.want {
				t.Errorf("%s was written as %s, but the reference writes %s",
					tc.given, got, tc.want)
			}
		})
	}
}

// A threshold that cannot be met founds an identity that can never sign again.
// The loss is silent until the first attempt to use it, which is why these are
// refused at the point the identity is made rather than left to a validator.
func TestUnmeetableThresholdsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given string
		keys  int
	}{
		{"more signatures than keys", `"4"`, 3},
		{"no signatures at all", `"0"`, 3},
		{"weights that never reach one", `["1/4","1/4"]`, 3},
		{"more weights than keys", `["1/2","1/2","1/2","1/2"]`, 3},
		{"a weight above one", `["3/2"]`, 3},
		{"a denominator of zero", `["1/0","1"]`, 3},
		{"not a number at all", `"two"`, 3},
		{"bare weights mixed with groups", `["1/2",["1"]]`, 3},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got, err := renderThreshold(json.RawMessage(tc.given), tc.keys, 1, "kt"); err == nil {
				t.Errorf("%s was accepted and written as %s, founding an identity that "+
					"could never sign", tc.given, got)
			}
		})
	}
}

// The defaults, which apply when an inception names no threshold. Getting these
// wrong produces a valid-looking identity with the wrong signing rule.
func TestThresholdDefaults(t *testing.T) {
	for _, tc := range []struct {
		count, floor int
		want         string
	}{
		{1, 1, `"1"`}, // one key: that key must sign
		{2, 1, `"1"`}, // ceil(2/2)
		{3, 1, `"2"`}, // ceil(3/2)
		{5, 1, `"3"`}, // ceil(5/2)
		{0, 0, `"0"`}, // no next keys committed: nothing to threshold
	} {
		got, err := renderThreshold(nil, tc.count, tc.floor, "kt")
		if err != nil {
			t.Fatalf("a default over %d keys was refused: %v", tc.count, err)
		}
		if string(got) != tc.want {
			t.Errorf("the default over %d keys is %s, but the reference computes %s",
				tc.count, got, tc.want)
		}
	}
}

// Witnesses and the toad, which are part of the identifier and are the other
// place an identity can be founded unusable.
func TestWitnessThresholdIsChecked(t *testing.T) {
	base := InceptionInput{
		Keys:        []string{"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"},
		NextDigests: []string{"EEXekUYwyf4Blv1U_WFML7YliBR9GJXfl3osKtIevKQN"},
	}
	wits := []string{
		"BMhTrQ8M0rYZrqks7sT9VqJNZJnVhM55JX5Fz9gTm2Cn",
		"BO4x-DyIpxIZpvz5vuDam8ImIFiPWhWmFFVTUE35ZJ5c",
	}

	refused := []struct {
		name string
		in   InceptionInput
	}{
		{"a toad no witness set could meet",
			InceptionInput{Keys: base.Keys, NextDigests: base.NextDigests, Witnesses: wits, Toad: 3}},
		{"witnesses named but none required",
			InceptionInput{Keys: base.Keys, NextDigests: base.NextDigests, Witnesses: wits, Toad: 0}},
		{"a toad with nothing to receipt it",
			InceptionInput{Keys: base.Keys, NextDigests: base.NextDigests, Toad: 1}},
		{"the same witness twice",
			InceptionInput{Keys: base.Keys, NextDigests: base.NextDigests,
				Witnesses: []string{wits[0], wits[0]}, Toad: 1}},
		{"the same key twice",
			InceptionInput{Keys: []string{base.Keys[0], base.Keys[0]},
				NextDigests: base.NextDigests}},
		{"no keys at all", InceptionInput{NextDigests: base.NextDigests}},
	}
	for _, tc := range refused {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got, err := BuildInception(tc.in); err == nil {
				t.Errorf("this was accepted, producing %s", got)
			}
		})
	}
}
