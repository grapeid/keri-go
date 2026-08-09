package keri

import (
	"encoding/json"
	"fmt"
)

// Answer produces this implementation's response to a conformance case.
//
// This is the seam the work happens behind. Each case kind is answered by one
// function; filling one in moves a group of cases from "not implemented" to
// either agreement or a visible disagreement, and nothing in between.
//
// It returns ErrNotImplemented rather than a wrong answer or an empty one. That
// distinction is the whole design of this harness: a missing answer is progress
// not yet made, a wrong answer is a claim that the rest of the world is wrong,
// and a suite that reported them identically would hide the second among the
// first.
func Answer(c Case) ([]byte, error) {
	switch c.Kind {
	case "inception":
		var in InceptionInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not an inception: %w", err)
		}
		return BuildInception(in)
	case "rotation":
		var in RotationInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not a rotation: %w", err)
		}
		return BuildRotation(in)
	case "interaction":
		var in InteractionInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not an interaction: %w", err)
		}
		return BuildInteraction(in)
	case "delegation":
		var in DelegationInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not a delegation: %w", err)
		}
		return BuildDelegation(in)
	case "credential":
		return AnswerCredential(c)
	case "receipt":
		return AnswerReceipt(c)
	case "stream":
		return AnswerStream(c)
	case "constants", "property", "reject":
		// Asserted directly by their own tests rather than by producing bytes.
		return nil, errAnsweredByAssert
	default:
		return nil, fmt.Errorf("no answer defined for a %q case", c.Kind)
	}
}

// InceptionInput is what founding an identity is given.
//
// Field names match the vector file, which matches the reference
// implementation's parameters. Named the same on purpose: a translation layer
// between what the vectors say and what this package calls things is somewhere
// for a mismatch to hide.
type InceptionInput struct {
	Keys        []string `json:"keys"`
	NextDigests []string `json:"next_digests"`
	Witnesses   []string `json:"witnesses"`
	Toad        int      `json:"toad"`
	// Thresholds are either a string ("2") or a list of weight strings
	// (["1/2","1/2","1/2"]). Kept as raw JSON so both forms the reference
	// produces can round-trip without the harness inventing a type.
	Isith json.RawMessage `json:"isith"`
	Nsith json.RawMessage `json:"nsith"`
	// Seals stay as raw bytes. A seal's field order is part of the event, and
	// Go marshals a map alphabetically, so any trip through one silently
	// reorders it and changes the identifier.
	Data []json.RawMessage `json:"data"`
}

// RotationInput is what changing an identity's keys is given.
type RotationInput struct {
	Prefix      string          `json:"prefix"`
	Keys        []string        `json:"keys"`
	PriorSAID   string          `json:"prior_said"`
	SN          int             `json:"sn"`
	NextDigests []string        `json:"next_digests"`
	Isith       json.RawMessage `json:"isith"`
	Nsith       json.RawMessage `json:"nsith"`
	// A rotation states witnesses as a DELTA against the set the identity
	// already has, so it needs that prior set to check the delta is applicable
	// as well as the cuts and adds themselves.
	PriorWitnesses []string `json:"prior_witnesses"`
	Cuts           []string `json:"cuts"`
	Adds           []string `json:"adds"`
	// A pointer because absent and zero are different answers: absent means
	// "derive the threshold", zero means "no witness need agree", and an int
	// could not tell them apart.
	Toad *int `json:"toad"`
	// Seals stay as raw bytes, for the reason given above.
	Data []json.RawMessage `json:"data"`
}

// InteractionInput is what anchoring something into a key history is given.
type InteractionInput struct {
	Prefix    string `json:"prefix"`
	PriorSAID string `json:"prior_said"`
	SN        int    `json:"sn"`
	// Seals stay as raw bytes. Their field order is part of the event, and any
	// trip through a Go map would sort it alphabetically and change the
	// identifier.
	Data []json.RawMessage `json:"data"`
}

// BuildInception lives in inception.go, BuildRotation in rotation.go.
//
// Each event kind is implemented in its own file so that the dispatch here
// stays a table of contents rather than an implementation.
