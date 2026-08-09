package keri

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture is a real delegation captured from keripy: a delegator whose key
// log anchors a delegated inception and then a delegated rotation, plus a
// delegated inception that was never anchored at all.
type delegationFixture struct {
	DelegatorKEL               []string `json:"delegator_kel"`
	DelegatorKELWithoutApprove []string `json:"delegator_kel_without_approval"`
	// A log whose seal names the right delegate at the right sequence number
	// but commits to a DIFFERENT event, so only the digest distinguishes them.
	DelegatorKELWrongDigest []string `json:"delegator_kel_wrong_digest"`
	DIP                     string   `json:"dip"`
	DRT                     string   `json:"drt"`
	RogueDIP                string   `json:"rogue_dip"`
	DelegatorPrefix         string   `json:"delegator_prefix"`
	DelegatePrefix          string   `json:"delegate_prefix"`
}

func loadDelegationFixture(t *testing.T) (delegationFixture, [][]byte, [][]byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("vectors", "delegation_authority_fixture.json"))
	if err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	var f delegationFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	decode := func(in []string) [][]byte {
		out := make([][]byte, len(in))
		for i, s := range in {
			raw, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				t.Fatal(err)
			}
			out[i] = raw
		}
		return out
	}
	return f, decode(f.DelegatorKEL), decode(f.DelegatorKELWithoutApprove)
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAnAnchoredDelegationIsAuthorised(t *testing.T) {
	f, kel, _ := loadDelegationFixture(t)
	for _, tc := range []struct {
		name  string
		event string
	}{
		{"delegated inception", f.DIP},
		{"delegated rotation", f.DRT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateDelegation(mustDecode(t, tc.event), kel); err != nil {
				t.Errorf("a delegation the delegator actually anchored was refused: %v", err)
			}
		})
	}
}

// The case the check exists for. A delegated inception names its own delegator,
// and that field is written by whoever built the event — so without this check
// an identity can claim an authority it was never granted and pass every
// structural test.
func TestAnUnanchoredDelegationIsRefused(t *testing.T) {
	f, kel, _ := loadDelegationFixture(t)
	err := ValidateDelegation(mustDecode(t, f.RogueDIP), kel)
	if err == nil {
		t.Fatal("a delegated inception that the delegator never anchored was accepted; " +
			"that is a forged delegation passing as a real one")
	}
	if !strings.Contains(err.Error(), "unauthorised") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// A delegator log that simply has not caught up yet must not read as approval.
func TestADelegationIsRefusedWhenTheApprovalIsAbsent(t *testing.T) {
	f, _, kelWithout := loadDelegationFixture(t)
	if err := ValidateDelegation(mustDecode(t, f.DIP), kelWithout); err == nil {
		t.Fatal("a delegation was accepted against a delegator log containing no seal " +
			"for it")
	}
}

// Supplying nothing must not read as "nothing was wrong".
func TestNoDelegatorLogIsNotApproval(t *testing.T) {
	f, _, _ := loadDelegationFixture(t)
	if err := ValidateDelegation(mustDecode(t, f.DIP), nil); err == nil {
		t.Fatal("an empty delegator log was treated as authorising the delegation")
	}
}

// An undelegated event has no delegation to authorise, and answering "valid"
// would be answering a different question than the caller asked.
func TestAnUndelegatedEventIsNotSilentlyApproved(t *testing.T) {
	_, kel, _ := loadDelegationFixture(t)
	if err := ValidateDelegation(kel[0], kel); err == nil {
		t.Fatal("a plain inception was accepted by the delegation check")
	}
}

// The seal names identifier, sequence number AND digest, and the digest is the
// part that does the work.
//
// This test previously used an event with a different identifier, which the
// check refuses on the identifier alone — so it passed without ever exercising
// the digest comparison it was named for. The fixture now anchors a seal naming
// the RIGHT delegate at the RIGHT sequence number, committing to a different
// event, so nothing but the digest can distinguish them.
//
// Matching on identifier and position alone would authorise a substituted event
// at that position, which is the exact substitution a key log exists to prevent.
func TestASealMustMatchTheDigestNotJustThePosition(t *testing.T) {
	f, _, _ := loadDelegationFixture(t)
	if len(f.DelegatorKELWrongDigest) == 0 {
		t.Skip("fixture predates the wrong-digest case")
	}
	kel := make([][]byte, len(f.DelegatorKELWrongDigest))
	for i, s := range f.DelegatorKELWrongDigest {
		kel[i] = mustDecode(t, s)
	}

	dip := mustDecode(t, f.DIP)
	ev, err := ParseEvent(dip)
	if err != nil {
		t.Fatal(err)
	}
	// Prove the fixture isolates the digest before trusting the verdict.
	anchoring, err := ParseEvent(kel[len(kel)-1])
	if err != nil {
		t.Fatal(err)
	}
	seals, err := anchoring.Seals()
	if err != nil {
		t.Fatal(err)
	}
	if len(seals) != 1 {
		t.Fatalf("expected exactly one seal to reason about, found %d", len(seals))
	}
	switch {
	case seals[0].Identifier != ev.Identifier:
		t.Fatal("the fixture no longer isolates the digest: the identifiers differ, so " +
			"a refusal proves nothing about digest checking")
	case seals[0].SN != ev.SN:
		t.Fatal("the fixture no longer isolates the digest: the sequence numbers differ")
	case seals[0].SAID == ev.SAID:
		t.Fatal("the fixture no longer isolates the digest: the digests are the same")
	}

	if err := ValidateDelegation(dip, kel); err == nil {
		t.Error("a delegation was authorised by a seal that names it at the right " +
			"position but commits to a different event — a substituted event would " +
			"pass as approved")
	}
}

func TestSealsAreReadFromTheAnchorField(t *testing.T) {
	f, kel, _ := loadDelegationFixture(t)
	var found bool
	for _, raw := range kel {
		ev, err := ParseEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		seals, err := ev.Seals()
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range seals {
			if s.Identifier == f.DelegatePrefix {
				found = true
			}
		}
	}
	if !found {
		t.Error("no seal naming the delegate was found in the delegator's log, so the " +
			"positive cases are passing for the wrong reason")
	}
}
