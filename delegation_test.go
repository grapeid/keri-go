package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// What the vectors cannot check.
//
// The two delegation vectors pin one dip and one drt exactly. What they do not
// pin is the RULE behind those bytes, and the rule is where this goes wrong
// silently: a dip built with basic derivation produces a well-formed event that
// verifies against itself and is rejected by every peer. These tests assert the
// rule rather than the one example of it.

const (
	testDelegator = "DDwTQ5qt7ZALf84a9z8pKH7J-dv6WVusPzBS627INFAw"
	testDelKey    = "DIhF3vq9I9ESHeDusRRv9OICVEnXrZUbvyWOZdnhxXOJ"
	testDelNext   = "EN2x2XGyNGz5_awXKfijVMNO3HTKSyEw188EZW9sBFiR"
)

func delFields(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("the event is not readable JSON: %v", err)
	}
	return m
}

func delStr(t *testing.T, m map[string]json.RawMessage, k string) string {
	t.Helper()
	v, ok := m[k]
	if !ok {
		t.Fatalf("the event has no %q field", k)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		t.Fatalf("%q is not a string: %v", k, err)
	}
	return s
}

// The derivation rule, stated as a test.
//
// A single-key ORDINARY inception takes basic derivation: the identifier is the
// key. A single-key DELEGATED inception does not get that choice — it is always
// self-addressing, because the identifier has to digest `di` and so commit to
// the delegator. Same key count, different rule; that is the whole point.
func TestDelegatedInceptionIsAlwaysSelfAddressing(t *testing.T) {
	raw, err := BuildDelegatedInception(DelegationInput{
		Delegator:   testDelegator,
		Keys:        []string{testDelKey},
		NextDigests: []string{testDelNext},
	})
	if err != nil {
		t.Fatalf("could not build a delegated inception: %v", err)
	}
	ev := delFields(t, raw)

	i, d := delStr(t, ev, "i"), delStr(t, ev, "d")
	if i != d {
		t.Errorf("a delegated inception is self-addressing, so i and d are one digest; "+
			"got i=%q d=%q", i, d)
	}
	if !strings.HasPrefix(i, CodeBlake3_256) {
		t.Errorf("the delegated identifier is %q, which is not a digest — this is the "+
			"basic-derivation mistake, and it yields an identity no peer accepts", i)
	}
	if i == testDelKey {
		t.Error("the delegated identifier is the signing key, so the delegator sits " +
			"outside it and could be swapped without changing who the identity is")
	}

	// The same inputs as an ORDINARY inception must take the other path, or
	// this test is passing for the wrong reason.
	plain, err := BuildInception(InceptionInput{
		Keys:        []string{testDelKey},
		NextDigests: []string{testDelNext},
	})
	if err != nil {
		t.Fatalf("could not build the comparison inception: %v", err)
	}
	if got := delStr(t, delFields(t, plain), "i"); got != testDelKey {
		t.Fatalf("an ordinary single-key inception should use basic derivation; got i=%q", got)
	}
}

// `di` is inside the digest, so it cannot be edited afterwards. Two delegated
// inceptions differing only in delegator must be two different identities.
func TestDelegatorIsPartOfTheDelegatedIdentifier(t *testing.T) {
	base := DelegationInput{
		Delegator:   testDelegator,
		Keys:        []string{testDelKey},
		NextDigests: []string{testDelNext},
	}
	a, err := BuildDelegatedInception(base)
	if err != nil {
		t.Fatalf("could not build: %v", err)
	}
	base.Delegator = "DGrnAMz14aKH81FEtvaxC4wAC6X_gnsFFwn5XQW3foDZ"
	b, err := BuildDelegatedInception(base)
	if err != nil {
		t.Fatalf("could not build: %v", err)
	}
	if delStr(t, delFields(t, a), "i") == delStr(t, delFields(t, b), "i") {
		t.Error("changing the delegator left the identifier the same, so the authority " +
			"this identity rests on could be rewritten without anyone noticing")
	}
	if delStr(t, delFields(t, a), "di") != testDelegator {
		t.Error("the delegated inception does not name its delegator")
	}
}

// A delegated rotation carries no `di`: the delegator was fixed at inception.
// Restating it would add bytes that say nothing new and could disagree with the
// founding event.
func TestDelegatedRotationCarriesNoDelegator(t *testing.T) {
	raw, err := BuildDelegatedRotation(DelegationInput{
		Prefix:      "EMLzUlDZeJxIl9EbP8fsBNek5N-FSc5xtaWrMlcTsI-I",
		PriorSAID:   "EMLzUlDZeJxIl9EbP8fsBNek5N-FSc5xtaWrMlcTsI-I",
		SN:          1,
		Keys:        []string{"DGrnAMz14aKH81FEtvaxC4wAC6X_gnsFFwn5XQW3foDZ"},
		NextDigests: []string{"EGc2GqjeY9H6sT5L4vvHB8-DAHiO5IgHHVAVgx8u5nzM"},
		Delegator:   testDelegator, // supplied, and deliberately not emitted
	})
	if err != nil {
		t.Fatalf("could not build a delegated rotation: %v", err)
	}
	ev := delFields(t, raw)
	if _, ok := ev["di"]; ok {
		t.Error("the delegated rotation emitted di; the reference does not, so these " +
			"bytes digest differently from every peer's")
	}
	if got := delStr(t, ev, "t"); got != "drt" {
		t.Errorf("the ilk is %q; a plain rot here is refused by anyone treating this "+
			"identity as delegated", got)
	}
	// The identifier is carried, not recomputed — recomputing would digest THIS
	// event rather than the founding one.
	if got := delStr(t, ev, "i"); got != "EMLzUlDZeJxIl9EbP8fsBNek5N-FSc5xtaWrMlcTsI-I" {
		t.Errorf("the rotation changed the identity's own identifier to %q", got)
	}
}

// Which event is built is decided by whether there is anything before it.
func TestDelegationDispatchesOnWhetherAnythingPrecedes(t *testing.T) {
	dip, err := BuildDelegation(DelegationInput{
		Delegator: testDelegator,
		Keys:      []string{testDelKey},
	})
	if err != nil {
		t.Fatalf("could not build: %v", err)
	}
	if got := delStr(t, delFields(t, dip), "t"); got != "dip" {
		t.Errorf("an input with no prior event should be a dip; got %q", got)
	}

	drt, err := BuildDelegation(DelegationInput{
		Prefix:    "EMLzUlDZeJxIl9EbP8fsBNek5N-FSc5xtaWrMlcTsI-I",
		PriorSAID: "EMLzUlDZeJxIl9EbP8fsBNek5N-FSc5xtaWrMlcTsI-I",
		SN:        1,
		Keys:      []string{"DGrnAMz14aKH81FEtvaxC4wAC6X_gnsFFwn5XQW3foDZ"},
	})
	if err != nil {
		t.Fatalf("could not build: %v", err)
	}
	if got := delStr(t, delFields(t, drt), "t"); got != "drt" {
		t.Errorf("an input chaining to a prior event should be a drt; got %q", got)
	}
}

func TestDelegationRefusesEventsNobodyCouldAccept(t *testing.T) {
	cases := []struct {
		name string
		in   DelegationInput
		why  string
	}{
		{
			"a delegated inception with no delegator",
			DelegationInput{Keys: []string{testDelKey}},
			"it claims an authority no one granted",
		},
		{
			"a delegated inception with no keys",
			DelegationInput{Delegator: testDelegator},
			"an identity founded on nothing can never sign",
		},
		{
			"a delegated rotation at sequence zero",
			DelegationInput{
				Prefix: "EMLzUlDZeJxIl9EbP8fsBNek5N-FSc5xtaWrMlcTsI-I",
				// PriorSAID present, so this is a rotation; sn 0 is the inception.
				PriorSAID: "EMLzUlDZeJxIl9EbP8fsBNek5N-FSc5xtaWrMlcTsI-I",
				SN:        0,
				Keys:      []string{testDelKey},
			},
			"sequence 0 is the delegated inception",
		},
		{
			"a delegated rotation naming no identity",
			DelegationInput{PriorSAID: "E123", SN: 1, Keys: []string{testDelKey}},
			"nothing says whose key history it belongs to",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := BuildDelegation(c.in); err == nil {
				t.Errorf("built %s, which should have been refused: %s", c.name, c.why)
			}
		})
	}
}
