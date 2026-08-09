package keri

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Two agents, each holding its own keys, exchanging key logs and believing each
// other only on the evidence.
//
// Everything else in this package tests a piece. This tests whether the pieces
// compose into the thing they exist for: an identity one party controls, that
// another party can verify without trusting the channel, that can rotate its
// keys and still be recognised, and that can anchor something the other party
// reads back.
//
// Nothing here is shared between the two agents except the bytes they send. In
// particular neither holds the other's keys, and the receiving side learns the
// sender's key state from the log rather than from being told.

// agent is one party: its own keys, its own log, and what it has learned about
// others. Deliberately small — the point is that this is all an agent needs.
type agent struct {
	name  string
	chain *Keychain
	// log is this agent's own key log, as signed messages.
	log [][]byte
	// prefix is this agent's identifier, once it exists.
	prefix string
	// known is what this agent has verified about other identities.
	known map[string]*SignedKELResult
}

func newAgent(t *testing.T, name string) *agent {
	t.Helper()
	chain, err := NewKeychain(NewMemoryKeyStore(), name, 1)
	if err != nil {
		t.Fatalf("%s could not create its keys: %v", name, err)
	}
	return &agent{name: name, chain: chain, known: map[string]*SignedKELResult{}}
}

// incept founds the agent's identity and returns the message announcing it.
func (a *agent) incept(t *testing.T) []byte {
	t.Helper()
	keys, err := a.chain.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	next, err := a.chain.NextDigests()
	if err != nil {
		t.Fatal(err)
	}
	icp, err := BuildInception(InceptionInput{Keys: keys, NextDigests: next})
	if err != nil {
		t.Fatalf("%s could not build its inception: %v", a.name, err)
	}
	signed, err := SignEvent(icp, a.chain.Signers()...)
	if err != nil {
		t.Fatalf("%s could not sign its inception: %v", a.name, err)
	}
	ev, err := ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	a.prefix = ev.Identifier
	a.log = append(a.log, signed.Message)
	return signed.Message
}

// lastEvent reads back the agent's most recent event, which the next one chains to.
func (a *agent) lastEvent(t *testing.T) *Event {
	t.Helper()
	raw, _, err := splitStream(a.log[len(a.log)-1])
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// anchor commits some seals into the agent's log with an interaction event.
func (a *agent) anchor(t *testing.T, seals ...json.RawMessage) []byte {
	t.Helper()
	prior := a.lastEvent(t)
	ixn, err := BuildInteraction(InteractionInput{
		Prefix:    a.prefix,
		PriorSAID: prior.SAID,
		SN:        int(prior.SN) + 1,
		Data:      seals,
	})
	if err != nil {
		t.Fatalf("%s could not build an interaction: %v", a.name, err)
	}
	signed, err := SignEvent(ixn, a.chain.Signers()...)
	if err != nil {
		t.Fatalf("%s could not sign its interaction: %v", a.name, err)
	}
	a.log = append(a.log, signed.Message)
	return signed.Message
}

// rotate moves the identity onto its committed successor keys.
func (a *agent) rotate(t *testing.T) []byte {
	t.Helper()
	prior := a.lastEvent(t)
	keys, next, err := a.chain.Rotate()
	if err != nil {
		t.Fatalf("%s could not rotate: %v", a.name, err)
	}
	rot, err := BuildRotation(RotationInput{
		Prefix:      a.prefix,
		Keys:        keys,
		PriorSAID:   prior.SAID,
		SN:          int(prior.SN) + 1,
		NextDigests: next,
	})
	if err != nil {
		t.Fatalf("%s could not build its rotation: %v", a.name, err)
	}
	// Signed with the keys the rotation puts in force, which are the ones the
	// previous event committed to.
	signed, err := SignEvent(rot, a.chain.Signers()...)
	if err != nil {
		t.Fatalf("%s could not sign its rotation: %v", a.name, err)
	}
	a.log = append(a.log, signed.Message)
	return signed.Message
}

// receive verifies another agent's log and records what it establishes.
//
// This is the whole trust decision, and it is made on the bytes alone.
func (a *agent) receive(messages [][]byte) (*SignedKELResult, error) {
	res, err := ValidateSignedKEL(messages)
	if err != nil {
		return nil, err
	}
	a.known[res.Identifier] = res
	return res, nil
}

func TestTwoAgentsEstablishAndVerifyEachOther(t *testing.T) {
	alice, bob := newAgent(t, "alice"), newAgent(t, "bob")
	alice.incept(t)
	bob.incept(t)

	if alice.prefix == bob.prefix {
		t.Fatal("two independently created identities have the same identifier")
	}

	// Each learns the other from the bytes, holding none of the other's keys.
	res, err := bob.receive(alice.log)
	if err != nil {
		t.Fatalf("bob could not verify alice's inception: %v", err)
	}
	if res.Identifier != alice.prefix {
		t.Errorf("bob verified %s, alice is %s", res.Identifier, alice.prefix)
	}
	aliceKeys, _ := alice.chain.CurrentKeys()
	if res.Keys[0] != aliceKeys[0] {
		t.Errorf("bob believes alice's key is %s, alice holds %s", res.Keys[0], aliceKeys[0])
	}

	if _, err := alice.receive(bob.log); err != nil {
		t.Fatalf("alice could not verify bob's inception: %v", err)
	}
}

// The exchange must survive a rotation: after alice changes her keys, bob must
// still recognise her as the same identity and must see the new key state.
func TestAnIdentitySurvivesRotationInTheOtherAgentsView(t *testing.T) {
	alice, bob := newAgent(t, "alice"), newAgent(t, "bob")
	alice.incept(t)
	before, err := bob.receive(alice.log)
	if err != nil {
		t.Fatal(err)
	}

	alice.rotate(t)
	after, err := bob.receive(alice.log)
	if err != nil {
		t.Fatalf("bob rejected alice's log after she rotated: %v", err)
	}

	if after.Identifier != before.Identifier {
		t.Error("rotating changed the identifier; the whole point of rotation is that " +
			"it does not")
	}
	if after.Keys[0] == before.Keys[0] {
		t.Fatal("the key state did not change across a rotation")
	}
	nowInForce, _ := alice.chain.CurrentKeys()
	if after.Keys[0] != nowInForce[0] {
		t.Errorf("bob believes alice's key is %s, alice now holds %s",
			after.Keys[0], nowInForce[0])
	}
	if after.Events != 2 {
		t.Errorf("bob verified %d events, expected 2", after.Events)
	}
}

// An agent anchors something; the other reads it back out of the verified log.
// This is the shape every real use takes — a delegation approval, a credential
// issuance, a commitment to a document are all seals in an interaction.
func TestOneAgentAnchorsSomethingTheOtherReadsBack(t *testing.T) {
	alice, bob := newAgent(t, "alice"), newAgent(t, "bob")
	alice.incept(t)
	bob.incept(t)

	// Alice commits to bob's identifier — the shape of a delegation approval.
	seal := json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`, bob.prefix, bob.prefix))
	alice.anchor(t, seal)

	if _, err := bob.receive(alice.log); err != nil {
		t.Fatalf("bob rejected alice's log after she anchored a seal: %v", err)
	}

	// Bob reads the seal out of the log he verified, not out of what he was told.
	var found bool
	for _, msg := range alice.log {
		raw, _, err := splitStream(msg)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := ParseEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		seals, err := ev.Seals()
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range seals {
			if s.Identifier == bob.prefix {
				found = true
			}
		}
	}
	if !found {
		t.Error("bob verified alice's log but could not find the seal she anchored")
	}
}

// The trust decision must be made on the evidence. Every one of these is a
// message an attacker could produce, and each must be refused.
func TestAnAgentRefusesWhatItCannotVerify(t *testing.T) {
	alice, bob := newAgent(t, "alice"), newAgent(t, "bob")
	alice.incept(t)
	alice.anchor(t, json.RawMessage(`{"note":"real"}`))

	if _, err := bob.receive(alice.log); err != nil {
		t.Fatalf("the honest log was refused, so the negative cases prove nothing: %v", err)
	}

	t.Run("a tampered event body", func(t *testing.T) {
		tampered := make([][]byte, len(alice.log))
		copy(tampered, alice.log)
		// Change the anchored content, leaving the signature as it was.
		tampered[1] = bytes.Replace(tampered[1], []byte(`"real"`), []byte(`"fake"`), 1)
		if _, err := bob.receive(tampered); err == nil {
			t.Error("a log whose anchored content was altered after signing was accepted")
		}
	})

	t.Run("an event with its signature removed", func(t *testing.T) {
		stripped := make([][]byte, len(alice.log))
		copy(stripped, alice.log)
		raw, _, err := splitStream(alice.log[1])
		if err != nil {
			t.Fatal(err)
		}
		stripped[1] = raw
		if _, err := bob.receive(stripped); err == nil {
			t.Error("an unsigned event was accepted into a verified log")
		}
	})

	t.Run("an event dropped from the middle", func(t *testing.T) {
		alice.rotate(t)
		gapped := [][]byte{alice.log[0], alice.log[2]}
		if _, err := bob.receive(gapped); err == nil {
			t.Error("a log with an event removed was accepted, so anything the missing " +
				"event did would be invisible")
		}
	})

	t.Run("someone else's inception claiming to continue the log", func(t *testing.T) {
		mallory := newAgent(t, "mallory")
		mallory.incept(t)
		spliced := [][]byte{alice.log[0], mallory.log[0]}
		if _, err := bob.receive(spliced); err == nil {
			t.Error("a log made of two different identities' events was accepted")
		}
	})
}

// An agent that has not seen a rotation must not accept an event signed by the
// key that rotation puts in force. Key state is what the log establishes, not
// what an event asserts.
func TestAnEventFromTheFutureIsNotAcceptedOutOfOrder(t *testing.T) {
	alice := newAgent(t, "alice")
	bob := newAgent(t, "bob")
	alice.incept(t)
	alice.rotate(t)

	// Only the inception and an event signed by the post-rotation key.
	withoutRotation := [][]byte{alice.log[0]}
	alice.anchor(t, json.RawMessage(`{"note":"after rotating"}`))
	withoutRotation = append(withoutRotation, alice.log[2])

	if _, err := bob.receive(withoutRotation); err == nil {
		t.Error("an event signed by keys the visible log never established was accepted")
	}
}

// Two agents' logs must not be confusable, even though both are valid.
func TestOneAgentsLogDoesNotValidateAsAnothers(t *testing.T) {
	alice, bob := newAgent(t, "alice"), newAgent(t, "bob")
	alice.incept(t)
	bob.incept(t)

	res, err := bob.receive(alice.log)
	if err != nil {
		t.Fatal(err)
	}
	if res.Identifier == bob.prefix {
		t.Fatal("alice's log established bob's identifier")
	}
	if _, ok := bob.known[bob.prefix]; ok {
		t.Error("verifying alice's log recorded something about bob")
	}
	if !strings.HasPrefix(res.Identifier, CodeEd25519) {
		t.Errorf("a single-key identity should be a basic identifier, got %s", res.Identifier)
	}
}
