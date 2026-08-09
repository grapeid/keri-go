package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// The rotation vectors do not exercise every branch a rotation has: none of
// them uses a fractional weighted threshold, an abandonment (no next keys), a
// sequence number past nine, or leaves the witness threshold to be derived.
// Those paths are the ones most likely to be got subtly wrong and least likely
// to be noticed, so the expectations below were taken from keripy 1.1.17 the
// same way the vector file was, by running the reference and recording what it
// produced.
//
// They live here rather than in vectors/ because that file is generated and is
// not ours to extend. If a case here ever conflicts with a vector, the vector
// wins.

const (
	rotTestPre   = "DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"
	rotTestPrior = "ENA99wILzMTehPTvcpeMlrd-6NwkAfl8LVRG6X6HyBOS"
)

func rotTestKeys() []string {
	return []string{
		"DBkgTIw7qFugWc0YrJAXvQKhjaXRDGj7d5o0vkPvBneR",
		"DOL-Kjm3MmZCgn1tgtSXYizWwpf-eCcOqkNrAfCGtvPL",
		"DFtkicnH_Q3PUFRefBZIhu9ASR7AbH8bEjBBeX6BF1Ne"}
}

func rotTestNexts() []string {
	return []string{
		"EFQFzi11-cRq9LVp9KPkp3jj-PYhhTH9zdnrcaLjfoRO",
		"EDUxc7jfdq2AvgXNSpq5jYFtURDsy0Tkqm1rAx7hwR6a",
		"EDVuXFCg2P6xr9UqII22JQdZ-h2oFIByikx3ArqTWIQQ"}
}

func rotTestWits() []string {
	return []string{
		"BMhTrQ8M0rYZrqks7sT9VqJNZJnVhM55JX5Fz9gTm2Cn",
		"BO4x-DyIpxIZpvz5vuDam8ImIFiPWhWmFFVTUE35ZJ5c",
		"BEdF0Zxm7JF5-iUJcFZAnvFpZ7ahp0v9j3r9Uo9ZYwYV",
		"BJZ_LF61JTCCGjhKn8Wf7JYSA0mfCBAe0Wrq4hkkTFOK"}
}

func TestRotationMatchesTheReferenceBeyondTheVectors(t *testing.T) {
	keys, nexts, wits := rotTestKeys(), rotTestNexts(), rotTestWits()
	base := func() RotationInput {
		return RotationInput{Prefix: rotTestPre, PriorSAID: rotTestPrior, SN: 1,
			Keys: keys, NextDigests: nexts}
	}

	tests := []struct {
		name string
		in   func() RotationInput
		want string
	}{{
		// A weighted threshold stays a LIST of strings. Collapsing it to a
		// count would still verify locally and would change who may sign.
		name: "a single clause of weights is written flat",
		in: func() RotationInput {
			in := base()
			in.Isith = json.RawMessage(`["1/2","1/2","1/2"]`)
			in.Nsith = json.RawMessage(`["1/3","1/3","1/3"]`)
			return in
		},
		want: `"kt":["1/2","1/2","1/2"]`,
	}, {
		// Several clauses stay nested, and a mixed event proves the two
		// threshold shapes coexist in one event.
		name: "several clauses stay nested alongside a count threshold",
		in: func() RotationInput {
			in := base()
			in.Isith = json.RawMessage(`[["1/2","1/2"],["1"]]`)
			in.Nsith = json.RawMessage(`"2"`)
			return in
		},
		want: `"kt":[["1/2","1/2"],["1"]],`,
	}, {
		// Weights are rationals, so "2/4" and "1/2" are the same threshold and
		// must serialise the same way — otherwise two peers building the same
		// event get two different identifiers.
		name: "weights are normalised as rationals",
		in: func() RotationInput {
			in := base()
			in.Isith = json.RawMessage(`["2/4","2/4","1/1"]`)
			in.Nsith = json.RawMessage(`["1/2","1/2","0"]`)
			return in
		},
		want: `"kt":["1/2","1/2","1"]`,
	}, {
		// Sequence numbers are hexadecimal. Sixteen is "10", and a decimal
		// implementation agrees for every event before the tenth.
		name: "the sequence number is hexadecimal",
		in: func() RotationInput {
			in := base()
			in.SN = 16
			return in
		},
		want: `"s":"10",`,
	}, {
		// Committing to no next keys is how an identity is abandoned; the next
		// threshold is then legitimately zero, which the current threshold may
		// never be.
		name: "abandonment commits to no future keys",
		in: func() RotationInput {
			in := base()
			in.NextDigests = nil
			return in
		},
		want: `"nt":"0","n":[],`,
	}, {
		// With no threshold stated the reference derives one that still
		// tolerates the most faults the set can survive — for four witnesses
		// that is three, not a bare majority of two.
		name: "an unstated witness threshold is derived, not defaulted to a majority",
		in: func() RotationInput {
			in := base()
			in.Adds = wits
			return in
		},
		want: `"bt":"3",`,
	}, {
		name: "a lone witness must always agree",
		in: func() RotationInput {
			in := base()
			in.Adds = wits[:1]
			return in
		},
		want: `"bt":"1",`,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildRotation(tc.in())
			if err != nil {
				t.Fatalf("could not build the rotation: %v", err)
			}
			if !strings.Contains(string(got), tc.want) {
				t.Errorf("expected the event to contain %s\ngot: %s", tc.want, got)
			}
			rotAssertSelfAddressing(t, got)
		})
	}
}

// The witness threshold the reference derives for each set size. Reproduced
// here because a derived threshold is invisible in the input: nothing about the
// event says the number was computed rather than chosen, so a wrong derivation
// looks exactly like a deliberate decision.
func TestTheDerivedWitnessThresholdMatchesTheReference(t *testing.T) {
	want := []int{0, 1, 2, 3, 3, 4, 4, 5, 6, 6, 7, 8, 8}
	for n, w := range want {
		if got := ample(n); got != w {
			t.Errorf("for %d witnesses the threshold should be %d, got %d", n, w, got)
		}
	}
}

// A rotation that could never be satisfied, or that describes a witness change
// the identity cannot make, is refused rather than built. Each of these would
// otherwise produce a well-formed event that permanently locks the identity out
// or that no peer can apply.
func TestRotationRefusesEventsNobodyCouldUse(t *testing.T) {
	keys, nexts, wits := rotTestKeys(), rotTestNexts(), rotTestWits()
	base := func() RotationInput {
		return RotationInput{Prefix: rotTestPre, PriorSAID: rotTestPrior, SN: 1,
			Keys: keys, NextDigests: nexts}
	}
	zero := 0

	tests := []struct {
		name string
		in   func() RotationInput
	}{{
		name: "sequence zero, which is the inception",
		in:   func() RotationInput { in := base(); in.SN = 0; return in },
	}, {
		name: "a threshold larger than the keys presented",
		in: func() RotationInput {
			in := base()
			in.Isith = json.RawMessage(`"4"`)
			return in
		},
	}, {
		name: "weights that cannot reach one",
		in: func() RotationInput {
			in := base()
			in.Isith = json.RawMessage(`["1/4","1/4","1/4"]`)
			return in
		},
	}, {
		name: "removing a witness the identity does not have",
		in:   func() RotationInput { in := base(); in.Cuts = wits[:1]; return in },
	}, {
		name: "adding a witness the identity already has",
		in: func() RotationInput {
			in := base()
			in.PriorWitnesses = wits[:2]
			in.Adds = wits[:1]
			return in
		},
	}, {
		name: "the same witness named twice",
		in: func() RotationInput {
			in := base()
			in.Adds = []string{wits[0], wits[0]}
			return in
		},
	}, {
		name: "witnesses with a threshold of zero, which is no protection at all",
		in: func() RotationInput {
			in := base()
			in.PriorWitnesses = wits[:2]
			in.Toad = &zero
			return in
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := BuildRotation(tc.in()); err == nil {
				t.Errorf("this should have been refused, but produced: %s", got)
			}
		})
	}
}

// rotAssertSelfAddressing checks the property the whole design rests on: the
// event's identifier is the digest of the event with that identifier blanked.
// Checked on every case above because it is the one error that produces bytes
// which look entirely correct until someone else verifies them.
func rotAssertSelfAddressing(t *testing.T, raw []byte) {
	t.Helper()
	var ev map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("the event is not readable: %v", err)
	}
	var said string
	if err := json.Unmarshal(ev["d"], &said); err != nil {
		t.Fatalf("the event carries no identifier: %v", err)
	}
	if len(said) != saidPlaceholderLen {
		t.Fatalf("the identifier is %d characters, not %d", len(said), saidPlaceholderLen)
	}
	blanked := make([]byte, len(raw))
	copy(blanked, raw)
	i := strings.Index(string(raw), said)
	if i < 0 {
		t.Fatalf("the identifier does not appear in the event")
	}
	for j := range said {
		blanked[i+j] = '#'
	}
	got, err := Blake3SAID(blanked)
	if err != nil {
		t.Fatalf("could not recompute the identifier: %v", err)
	}
	if got != said {
		t.Errorf("the event says its identifier is %s but its bytes digest to %s",
			said, got)
	}
}
