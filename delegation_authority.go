package keri

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Whether a delegation was actually authorised.
//
// ValidateKEL checks a delegated event as an event and as a link in its own
// chain, and says so explicitly: it does not check that the DELEGATOR agreed.
// That question cannot be answered from the delegate's key log alone, because
// the approval lives in a different log entirely.
//
// The gap matters. A delegated inception names its delegator in `di`, and that
// field is written by whoever built the event — so an unchecked delegated
// identity is one that claims an authority nobody verified it was given. It
// would pass every structural check and be, in substance, forged.
//
// The approval is a seal: the delegator anchors {i, s, d} — the delegate's
// identifier, the sequence number of the delegated event, and its digest — in
// the `a` field of one of its own events. Naming all three is what makes the
// approval specific: a seal that named only the identifier would authorise
// every event that identity ever produces.

// Seal is an anchor carried in an event's `a` field.
type Seal struct {
	Identifier string
	SN         uint64
	SAID       string
}

// sealWire is a seal as it appears on the wire. Only the three fields that
// constitute a delegation approval are read; a seal carrying others is not
// rejected, because `a` anchors things other than delegations.
type sealWire struct {
	I string `json:"i"`
	S string `json:"s"`
	D string `json:"d"`
}

// Seals returns the anchors in an event's `a` field.
//
// An event with no `a` field, or an empty one, has no seals and that is not an
// error — most events anchor nothing.
func (e *Event) Seals() ([]Seal, error) {
	var raw []byte
	for _, f := range e.Fields {
		if f.Name == "a" {
			raw = f.Value
			break
		}
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var wire []sealWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		// `a` is a list of seals on the events that can anchor one. On an
		// establishment event it may carry other shapes, which is not this
		// function's business to reject.
		return nil, nil
	}
	out := make([]Seal, 0, len(wire))
	for _, w := range wire {
		if w.I == "" || w.D == "" {
			// Not a delegation-shaped seal. Skipped rather than refused: `a`
			// legitimately anchors other things.
			continue
		}
		sn, err := strconv.ParseUint(w.S, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("a seal for %s has sequence number %q, which is not "+
				"hexadecimal", w.I, w.S)
		}
		out = append(out, Seal{Identifier: w.I, SN: sn, SAID: w.D})
	}
	return out, nil
}

// ValidateDelegation reports whether a delegator's key log authorises a
// delegated event.
//
// `delegated` is the dip or drt being checked. `delegatorKEL` is the delegator's
// own key log, in order, which is validated in full first — an approval anchored
// in a log that does not hold up is not an approval.
//
// A delegated inception names its delegator; a delegated rotation does not carry
// `di` at all, so for a drt the delegator is taken from whose log is supplied.
// That is the reference's shape, confirmed against the vectors, and it is why
// this function needs the log rather than just the event.
func ValidateDelegation(delegated []byte, delegatorKEL [][]byte) error {
	ev, err := ParseEvent(delegated)
	if err != nil {
		return fmt.Errorf("the delegated event is not readable: %w", err)
	}
	switch ev.Ilk {
	case "dip", "drt":
	default:
		return fmt.Errorf("a %s event is not delegated, so there is no delegation to "+
			"authorise", ev.Ilk)
	}
	if len(delegatorKEL) == 0 {
		return fmt.Errorf("no delegator key log was supplied, so whether %s was "+
			"authorised cannot be established — treat it as unauthorised rather "+
			"than as valid", ev.Identifier)
	}

	// The approval is only worth as much as the log it sits in.
	if err := ValidateKEL(delegatorKEL); err != nil {
		return fmt.Errorf("the delegator's own key log does not hold up, so nothing "+
			"anchored in it can be relied on: %w", err)
	}

	delegator, err := ParseEvent(delegatorKEL[0])
	if err != nil {
		return fmt.Errorf("the delegator's inception is not readable: %w", err)
	}
	// A delegated inception says who it believes its delegator is. If that
	// disagrees with the log supplied, one of the two is about a different
	// identity and answering "authorised" would be answering a question nobody
	// asked.
	if ev.Ilk == "dip" && ev.Delegator != "" && ev.Delegator != delegator.Identifier {
		return fmt.Errorf("the event names %s as its delegator but the key log supplied "+
			"is %s", ev.Delegator, delegator.Identifier)
	}

	for _, raw := range delegatorKEL {
		anchoring, err := ParseEvent(raw)
		if err != nil {
			// ValidateKEL already passed, so this cannot normally happen;
			// reported rather than skipped so a future change cannot make the
			// search quietly incomplete.
			return fmt.Errorf("an event in the delegator's log became unreadable: %w", err)
		}
		seals, err := anchoring.Seals()
		if err != nil {
			return fmt.Errorf("a seal in the delegator's log at sn %d is malformed: %w",
				anchoring.SN, err)
		}
		for _, s := range seals {
			// All three must match. The identifier alone would authorise every
			// event that identity ever produces; the identifier and sequence
			// number without the digest would authorise a substituted event at
			// the same position, which is the exact substitution a key log
			// exists to prevent.
			if s.Identifier == ev.Identifier && s.SN == ev.SN && s.SAID == ev.SAID {
				return nil
			}
		}
	}

	return fmt.Errorf("%s at sn %d (%s) is not anchored anywhere in %s's key log, so the "+
		"delegation is unauthorised", ev.Identifier, ev.SN, ev.SAID, delegator.Identifier)
}
