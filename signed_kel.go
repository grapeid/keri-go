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
		// priorNext and priorNextTh are the commitment of the last
		// establishment event: what the next rotation must open. An
		// interaction carries none, so it never changes them.
		priorNext   []string
		priorNextTh *parsedThreshold
		result      SignedKELResult
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

		// An establishment event sets the state, and its own keys are the
		// right thing to check its signatures against. What makes them more
		// than self-asserted, for a rotation, is the check below that the keys
		// which signed open enough of the previous commitment.
		rotation := ev.Ilk == "rot" || ev.Ilk == "drt"
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
		verified := verifyAgainstKeyState(fs, ev, attachments[i], keys, threshold)
		if rotation {
			checkPriorNextOpened(fs, ev, verified, priorNext, priorNextTh)
		}
		if ev.Establishment() {
			priorNext, priorNextTh = ev.NextDigest, ev.NextThreshold
		}
	}

	if err := fs.err(); err != nil {
		return nil, err
	}
	result.Keys = keys
	result.Threshold = threshold
	result.Events = len(events)
	return &result, nil
}

// verifyControllerSignatures checks an event's controller signatures against a
// key list. It returns the ones that verified, each at most once, and how many
// were dropped because they did not verify.
//
// The key list is the event's own for an establishment event and the key state
// in force for an interaction; the caller decides which.
//
// A signature that does not verify is dropped and the rest are judged, as
// keripy 1.3.6 does: it attests nothing, and it never counts toward any
// threshold. Refusing the whole event over it would let anyone who passes the
// event along make a valid event unverifiable by appending junk. A signature
// naming a place outside the key list is still a fault, as it is in keripy,
// and so is a key that cannot be read.
func verifyControllerSignatures(fs *faults, ev *Event, groups []attachment,
	keys []string) (verified []indexedSig, dropped int) {

	seen := make(map[string]bool)
	for _, g := range groups {
		if g.Counter != counterControllerIdxSigs {
			continue
		}
		for _, sig := range g.Sigs {
			if seen[sig.QB64] {
				continue // the same signature twice is one signature
			}
			seen[sig.QB64] = true
			if sig.Index < 0 || sig.Index >= len(keys) {
				fs.add(FaultSignatureInvalid, "a signature claims key %d and the key "+
					"list holds %d keys", sig.Index, len(keys))
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
				dropped++
				continue
			}
			verified = append(verified, sig)
		}
	}
	return verified, dropped
}

// verifyAgainstKeyState checks an event's controller signatures against a key
// state and its signing threshold, and returns the signatures that verified.
func verifyAgainstKeyState(fs *faults, ev *Event, groups []attachment,
	keys []string, threshold *parsedThreshold) []indexedSig {

	verified, dropped := verifyControllerSignatures(fs, ev, groups, keys)
	signed := make(map[int]bool, len(verified))
	for _, sig := range verified {
		signed[sig.Index] = true
	}
	// Said in the refusal, so a reader can tell a forgery from a short count.
	unverified := ""
	if dropped > 0 {
		unverified = fmt.Sprintf("; %d attached signature(s) did not verify over this "+
			"event and were not counted", dropped)
	}
	if len(signed) == 0 {
		fs.add(FaultThresholdNotMet, "the event arrives with no controller signature "+
			"that verifies under the keys it must be signed by, so nothing attests "+
			"that its controller produced it%s", unverified)
		return verified
	}
	if threshold != nil && !threshold.satisfiedBy(signed) {
		fs.add(FaultThresholdNotMet, "%d of %d keys signed, which does not meet the "+
			"signing threshold in force%s", len(signed), len(keys), unverified)
	}
	return verified
}

// checkPriorNextOpened is the rule that makes a rotation safe, with the
// signatures in hand.
//
// The previous establishment event published DIGESTS of the keys that would
// come next, and a threshold over them. A rotation is authorised by the prior
// commitments its signing keys open: a signature that carries a prior-next
// place (every code but the current-only ones) opens that place when the key it
// was made with digests to the commitment there. The places opened must meet
// the prior next threshold. A key that is merely listed in k, without signing,
// opens nothing — counting listed keys is how a rotation signed by too few of
// the committed keys would pass.
//
// Each opened place counts once, which is stricter than keripy 1.3.6: it
// counts a place once per signature opening it, so one key written twice can
// meet a prior next threshold of two alone (see satisfiedBy).
//
// Otherwise this is keripy's Kever.exposeds and its prior-next check: a signature
// whose prior-next place is outside the commitment, or whose key does not
// digest to the commitment there, simply opens nothing. It is not a fault on
// its own, because the same signature may still count toward the new kt.
func checkPriorNextOpened(fs *faults, ev *Event, verified []indexedSig,
	committed []string, th *parsedThreshold) {

	opened := make(map[int]bool)
	for _, sig := range verified {
		if !sig.HasOndex || sig.Ondex < 0 || sig.Ondex >= len(committed) {
			continue
		}
		digest, err := Blake3SAID([]byte(ev.Keys[sig.Index]))
		if err != nil || digest != committed[sig.Ondex] {
			continue
		}
		opened[sig.Ondex] = true
	}
	if !th.satisfiedBy(opened) {
		fs.add(FaultThresholdNotMet, "the keys that signed open %d of the %d keys the "+
			"previous establishment event committed to, which does not meet the next "+
			"threshold it set, so this rotation was not authorised by the committed keys",
			len(opened), len(committed))
	}
}
