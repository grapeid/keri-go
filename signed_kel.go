package keri

import (
	"crypto/ed25519"
	"fmt"
)

// Verifying a key log against the key state it establishes.
//
// ValidateStream checks the signatures on an ESTABLISHMENT event against the
// keys that event carries. That is right for an inception or a rotation, whose
// keys are declared in the event itself and, for a rotation, checked against the
// digest the previous event committed to.
//
// It leaves a hole: an interaction event carries no keys, so nothing was
// verified for it at all. An interaction is not a minor event — it is what
// anchors things. A delegation approval is a seal in an interaction, and so is a
// credential issuance. An unverified interaction means anyone can fabricate one
// anchoring whatever they like, and every check that reads those anchors —
// including ValidateDelegation — is reading a forgery.
//
// The fix is to carry the key state forward. An establishment event sets the
// keys and the threshold; every event after it, until the next establishment
// event, must be signed by that state.

// SignedKELResult is what a verified log establishes.
type SignedKELResult struct {
	Identifier string
	// Keys and Threshold are the state in force after the last event.
	Keys      []string
	Threshold *parsedThreshold
	// Events is how many events were verified.
	Events int
}

// ValidateSignedKEL checks a key log whose entries carry their attachments.
//
// Each message is an event followed by its CESR attachments, as it travels. The
// log is validated structurally first — order, chaining, pre-rotation — and then
// every event's controller signatures are verified against the key state in
// force at that point in the log, rather than against whatever the event
// happens to carry.
//
// The difference matters most for interaction events, which carry no keys and
// were previously not signature-checked at all.
func ValidateSignedKEL(messages [][]byte) (*SignedKELResult, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("an empty log establishes no identity")
	}

	events := make([][]byte, 0, len(messages))
	attachments := make([][]attachment, 0, len(messages))
	for i, msg := range messages {
		raw, attached, err := splitStream(msg)
		if err != nil {
			return nil, fmt.Errorf("message %d is not an event with attachments: %w", i, err)
		}
		groups, err := parseAttachments(attached)
		if err != nil {
			return nil, fmt.Errorf("message %d has unreadable attachments: %w", i, err)
		}
		events = append(events, raw)
		attachments = append(attachments, groups)
	}

	// Structure first. Verifying signatures on a log that does not chain would
	// be answering a narrower question than the caller asked.
	if err := ValidateKEL(events); err != nil {
		return nil, err
	}

	fs := &faults{}
	var (
		keys      []string
		threshold *parsedThreshold
		result    SignedKELResult
	)

	for i, raw := range events {
		ev, err := ParseEvent(raw)
		if err != nil {
			// ValidateKEL passed, so this cannot normally happen. Reported
			// rather than skipped so a future change cannot silently stop
			// verifying part of the log.
			return nil, fmt.Errorf("event %d became unreadable: %w", i, err)
		}
		if i == 0 {
			result.Identifier = ev.Identifier
		}

		// An establishment event sets the state. Its own keys are the right
		// thing to check it against: ValidateKEL has already confirmed that a
		// rotation presents keys the previous event committed to by digest, so
		// they are not self-asserted.
		if ev.Establishment() {
			keys = ev.Keys
			threshold = ev.SigThreshold
		}
		if len(keys) == 0 {
			fs.add(FaultMalformed, "event %d (%s at sn %d) has no key state to check "+
				"against, because no establishment event preceded it", i, ev.Ilk, ev.SN)
			continue
		}

		fs.at(fmt.Sprintf("event %d (%s at sn %d)", i, ev.Ilk, ev.SN))
		verifyAgainstKeyState(fs, ev, attachments[i], keys, threshold)
	}

	if err := fs.err(); err != nil {
		return nil, err
	}
	result.Keys = keys
	result.Threshold = threshold
	result.Events = len(events)
	return &result, nil
}

// verifyAgainstKeyState checks an event's controller signatures against a key
// state supplied from outside the event.
func verifyAgainstKeyState(fs *faults, ev *Event, groups []attachment,
	keys []string, threshold *parsedThreshold) {

	signed := make(map[int]bool)
	for _, g := range groups {
		if g.Counter != counterControllerIdxSigs {
			continue
		}
		for _, sig := range g.Sigs {
			if sig.Index < 0 || sig.Index >= len(keys) {
				fs.add(FaultSignatureInvalid, "a signature claims key %d and the key "+
					"state holds %d keys", sig.Index, len(keys))
				continue
			}
			pub, err := MatterRaw(CodeEd25519, keys[sig.Index], ed25519.PublicKeySize)
			if err != nil {
				pub, err = MatterRaw(CodeEd25519N, keys[sig.Index], ed25519.PublicKeySize)
			}
			if err != nil {
				fs.add(FaultSignatureInvalid, "key %d (%s) is not a readable Ed25519 "+
					"public key: %v", sig.Index, keys[sig.Index], err)
				continue
			}
			if !ed25519.Verify(pub, ev.Raw, sig.Raw) {
				fs.add(FaultSignatureInvalid, "the signature attached for key %d (%s) "+
					"does not verify over this event, so whoever produced it did not "+
					"hold that key", sig.Index, keys[sig.Index])
				continue
			}
			signed[sig.Index] = true
		}
	}

	if len(signed) == 0 {
		fs.add(FaultThresholdNotMet, "the event arrives with no controller signature "+
			"that verifies under the identity's established keys, so nothing attests "+
			"that its controller produced it")
		return
	}
	if threshold != nil && !threshold.satisfiedBy(signed, len(keys)) {
		fs.add(FaultThresholdNotMet, "%d of %d established keys signed, which does not "+
			"meet the threshold in force", len(signed), len(keys))
	}
}
