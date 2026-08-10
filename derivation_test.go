package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// A single-key identity may legitimately be self-addressing, and a caller must
// be able to ask for that.
//
// The reference infers derivation from the key count unless told otherwise, and
// this package used to infer it with no override — which meant it could not
// produce the identifiers of an application that had issued self-addressing
// single-key identities. Found by comparing against a real deployment, not by
// reading the specification.
func TestASingleKeyIdentityCanBeSelfAddressing(t *testing.T) {
	in := InceptionInput{
		Keys:        []string{"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"},
		NextDigests: []string{"EEXekUYwyf4Blv1U_WFML7YliBR9GJXfl3osKtIevKQN"},
	}

	byDefault, err := BuildInception(in)
	if err != nil {
		t.Fatal(err)
	}
	defaultEv, err := ParseEvent(byDefault)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(defaultEv.Identifier, CodeEd25519) {
		t.Errorf("one key with no derivation stated should be basic, got %s",
			defaultEv.Identifier)
	}

	in.Derivation = "self-addressing"
	forced, err := BuildInception(in)
	if err != nil {
		t.Fatalf("self-addressing was refused for a single key: %v", err)
	}
	forcedEv, err := ParseEvent(forced)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(forcedEv.Identifier, CodeBlake3_256) {
		t.Errorf("forcing self-addressing produced %s, which is not digest-derived",
			forcedEv.Identifier)
	}
	// On a self-addressing event the identifier IS the SAID.
	var ev struct{ D, I string }
	if err := json.Unmarshal(forced, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.D != ev.I {
		t.Errorf("a self-addressing event must have d == i, got d=%s i=%s", ev.D, ev.I)
	}
	if forcedEv.Identifier == defaultEv.Identifier {
		t.Error("forcing the derivation changed nothing")
	}
}

func TestDerivationRefusesWhatItCannotDo(t *testing.T) {
	two := InceptionInput{
		Keys: []string{
			"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd",
			"DC3wQSXwAVr7R86FOu-HcglP-UmMFMsbnhKXPCkn2g-m",
		},
		NextDigests: []string{"EEXekUYwyf4Blv1U_WFML7YliBR9GJXfl3osKtIevKQN"},
		Derivation:  "basic",
	}
	if _, err := BuildInception(two); err == nil {
		t.Error("basic derivation was accepted with two keys, but the identifier can " +
			"only be one of them")
	}
	one := InceptionInput{
		Keys:        []string{"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"},
		NextDigests: []string{"EEXekUYwyf4Blv1U_WFML7YliBR9GJXfl3osKtIevKQN"},
		Derivation:  "nonsense",
	}
	if _, err := BuildInception(one); err == nil {
		t.Error("an unknown derivation name was accepted")
	}
}
