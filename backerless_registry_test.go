package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// A registry whose events are witnessed only through its issuer's own log is
// founded with the configuration trait "NB" (no backers), `bt` "0" and an empty
// `b`, as keripy's `incept(..., noBackers=True)` writes it. Without the trait a
// registry may add backers later, so a verifier could not tell that its only
// witnessing is the issuer's.
func TestABackerlessRegistryCarriesTheNBTrait(t *testing.T) {
	issuer := "DGLDzhg7VO1UEFOs4Av-gUU7hcRbdvyO_5nw7IbKBrQt"
	built, err := BuildRegistryInception(RegistryInput{Issuer: issuer, Nonce: "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2", NoBackers: true})
	if err != nil {
		t.Fatalf("could not found a backerless registry: %v", err)
	}
	ev, err := VerifyTELEvent(built)
	if err != nil {
		t.Fatalf("the registry does not verify: %v", err)
	}
	if ev.Issuer != issuer || len(ev.Traits) != 1 || ev.Traits[0] != "NB" || len(ev.Backers) != 0 {
		t.Fatalf("read back issuer %q traits %v backers %v", ev.Issuer, ev.Traits, ev.Backers)
	}
	if !strings.Contains(string(built), `"c":["NB"],"bt":"0","b":[]`) {
		t.Fatalf("the registry is not written as keripy writes a backerless one: %s", built)
	}
	// it is a different registry from one without the trait
	plain, _ := BuildRegistryInception(RegistryInput{Issuer: issuer, Nonce: "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2"})
	pv, _ := VerifyTELEvent(plain)
	if pv.SAID == ev.SAID || len(pv.Traits) != 0 {
		t.Fatal("the trait did not change the registry's identifier")
	}
	// no backers and the trait contradict each other
	if _, err := BuildRegistryInception(RegistryInput{Issuer: issuer, Nonce: "n", NoBackers: true,
		Backers: []string{"BDKrJxkcR9m5u1xs33F5pxRJP6T7hJEbhpHrUtlDdhh0"}, Toad: 1}); err == nil {
		t.Fatal("a registry with no backers was given a backer")
	}
}

// Anything but the one trait this package can write is read back as it is, and
// a registry that says something else in c is not a backerless one to a caller
// that checks.
func TestARegistryEventReadsBackItsOwnFields(t *testing.T) {
	built, _ := BuildRegistryInception(RegistryInput{Issuer: "DGLDzhg7VO1UEFOs4Av-gUU7hcRbdvyO_5nw7IbKBrQt", Nonce: "n"})
	ev, err := VerifyTELEvent(built)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Traits) != 0 || len(ev.Backers) != 0 || ev.BackerThreshold != "0" {
		t.Fatalf("a plain registry read back as %+v", ev)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(built, &m)
}
