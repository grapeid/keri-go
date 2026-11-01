package keri

import "fmt"

// Verifying one key event against the key state it follows.
//
// ValidateSignedKEL answers whether a whole log holds together. A party that
// already holds an identity's verified log — a witness, a watcher, an agent
// keeping a peer's log — asks a narrower question each time an event arrives:
// does this one event follow from what is already known? Re-verifying the whole
// log for every event answers it, at a cost that grows with the log.
//
// So the rules are written once, as a step from one key state to the next
// (advance), and both questions are answered with it: ValidateKEL and
// ValidateSignedKEL fold it over a log, and VerifyEvent and Admit apply it to
// one event. An event that VerifyEvent accepts after a log's last state is
// exactly an event that ValidateSignedKEL accepts at the end of that log.

// KeyState is an identity's key state after one event of its log: the keys in
// force, the commitment the next rotation must open, and the witnesses.
//
// It has no exported constructor. A KeyState is something this package
// established by verifying events, never something a caller asserts, so the
// only ways to get one are ValidateSignedKEL (State, StateAt), VerifyEvent and
// Admit.
type KeyState struct {
	identifier string
	sn         uint64
	digest     string
	ilk        string

	keys      []string
	threshold *parsedThreshold

	// next and nextThreshold are the commitment of the last establishment
	// event: what the next rotation must open. An interaction carries none, so
	// it never changes them.
	next          []string
	nextThreshold *parsedThreshold
	// establishment is the sequence number of the last establishment event,
	// and established whether there has been one.
	establishment uint64
	established   bool

	witnesses []string
	toad      uint64
}

// Identifier is the identity this state belongs to.
func (s *KeyState) Identifier() string { return s.identifier }

// SN is the sequence number of the event this state follows.
func (s *KeyState) SN() uint64 { return s.sn }

// Digest is the SAID of the event this state follows: what the next event's
// prior digest must be.
func (s *KeyState) Digest() string { return s.digest }

// Ilk is the type of the event this state follows.
func (s *KeyState) Ilk() string { return s.ilk }

// Keys are the signing keys in force.
func (s *KeyState) Keys() []string { return append([]string(nil), s.keys...) }

// NextDigests is the next-key commitment the next rotation must open.
func (s *KeyState) NextDigests() []string { return append([]string(nil), s.next...) }

// LastEstablishment is the sequence number of the last establishment event.
// A recovery rotation may replace only the interactions after it.
func (s *KeyState) LastEstablishment() uint64 { return s.establishment }

// Witnesses are the witnesses designated for the next event.
func (s *KeyState) Witnesses() []string { return append([]string(nil), s.witnesses...) }

// TOAD is the witness threshold in force.
func (s *KeyState) TOAD() uint64 { return s.toad }

// advance applies ev, which is to follow prev (nil for the first event of a
// log), and returns the state after it. Every fault goes to fs; the state is
// returned whatever was found, so a caller folding a log can report the faults
// of later events too.
//
// With signed false it checks what can be said without signatures, which is
// ValidateKEL's question; with signed true it also verifies the controller
// signatures against the key state in force and counts the witness signatures,
// which is ValidateSignedKEL's.
func advance(fs *faults, prev *KeyState, ev *Event, groups []attachment,
	signed bool) (*KeyState, EventWitnessing) {

	st := &KeyState{}
	if prev == nil {
		if ev.Ilk != "icp" && ev.Ilk != "dip" {
			fs.add(FaultMalformed, "a key history begins with an inception, and this "+
				"one begins with a %s", ev.Ilk)
		}
		if ev.SN != 0 {
			fs.add(FaultSequenceSkip, "an inception is at sequence number 0, and this "+
				"one claims %d", ev.SN)
		}
		st.identifier = ev.Identifier
	} else {
		*st = *prev
		if ev.Ilk == "icp" || ev.Ilk == "dip" {
			fs.add(FaultMalformed, "an identity is founded once, and this log carries a "+
				"second inception at sequence number %d", ev.SN)
		}
		if ev.Identifier != prev.identifier {
			fs.add(FaultIdentifierMismatch, "this event belongs to %s and the log is the "+
				"history of %s", ev.Identifier, prev.identifier)
		}
		if ev.SN != prev.sn+1 {
			fs.add(FaultSequenceSkip, "sequence number %d does not follow the prior "+
				"event at %d, so an event has been inserted or dropped", ev.SN, prev.sn)
		}
		if ev.PriorSAID != prev.digest {
			fs.add(FaultPriorDigestMismatch, "this event digests its predecessor as %s "+
				"but the previous event is %s, so it belongs to a different history",
				ev.PriorSAID, prev.digest)
		}
	}
	st.sn, st.digest, st.ilk = ev.SN, ev.SAID, ev.Ilk

	rotation := ev.Ilk == "rot" || ev.Ilk == "drt"
	if rotation {
		if prev != nil && prev.established {
			checkPrecommitment(fs, ev, prev.next, prev.nextThreshold)
		}
		var current []string
		if prev != nil {
			current = prev.witnesses
		}
		checkWitnessChange(fs, ev, current)
		st.witnesses = applyWitnessChange(current, ev)
		if ev.HasTOAD && ev.TOAD > uint64(len(st.witnesses)) {
			fs.add(FaultTOADExceedsWitnesses, "the rotation sets a witness parsedThreshold of "+
				"%d against %d witnesses", ev.TOAD, len(st.witnesses))
		}
	}
	if ev.Establishment() {
		if !rotation {
			st.witnesses = append([]string(nil), ev.Witnesses...)
		}
		st.keys, st.threshold = ev.Keys, ev.SigThreshold
		st.next, st.nextThreshold = ev.NextDigest, ev.NextThreshold
		st.establishment, st.established = ev.SN, true
		st.toad = ev.TOAD
	}

	var w EventWitnessing
	if !signed {
		return st, w
	}
	// An establishment event's own keys are the right thing to check its
	// signatures against. What makes them more than self-asserted, for a
	// rotation, is that the keys which signed open enough of the previous
	// commitment.
	w = countWitnessSignatures(ev, groups, st.witnesses, st.toad)
	if len(st.keys) == 0 {
		fs.add(FaultMalformed, "the %s at sn %d has no key state to check against, "+
			"because no establishment event preceded it", ev.Ilk, ev.SN)
		return st, w
	}
	verified := verifyAgainstKeyState(fs, ev, groups, st.keys, st.threshold)
	if rotation {
		var committed []string
		var th *parsedThreshold
		if prev != nil {
			committed, th = prev.next, prev.nextThreshold
		}
		checkPriorNextOpened(fs, ev, verified, committed, th)
	}
	return st, w
}

// Verified is one event verified against the key state it follows.
type Verified struct {
	// State is the key state after the event.
	State *KeyState
	// Witnessing is what the event's witness-indexed signatures establish.
	// It is reported and not enforced, as in ValidateSignedKEL.
	Witnessing EventWitnessing
}

// VerifyEvent checks one event, with its attachments as it travels, against the
// key state it is to follow, and returns the state after it. A nil state means
// the event is the identity's founding.
//
// It applies every rule ValidateSignedKEL applies to an event in a log: the
// event is well formed, it is the next sequence number of the same identity and
// digests the event the state follows, a rotation's keys open enough of the
// last establishment event's commitment and change the witnesses correctly, and
// its controller signatures meet the threshold in force. As there, a signature
// that does not verify is dropped and the rest are judged.
func VerifyEvent(state *KeyState, message []byte) (*Verified, error) {
	ev, groups, fs, err := readMessage(message)
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, fs.err()
	}
	next, w := advance(fs, state, ev, groups, true)
	if err := fs.err(); err != nil {
		return nil, err
	}
	return &Verified{State: next, Witnessing: w}, nil
}

// readMessage splits an event from its attachments and checks what can be
// decided from the event alone. ev is nil when the bytes are not an event, and
// the reason is in fs.
func readMessage(message []byte) (*Event, []attachment, *faults, error) {
	raw, attached, err := splitStream(message)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("not an event with attachments: %w", err)
	}
	groups, err := parseAttachments(attached)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unreadable attachments: %w", err)
	}
	fs := &faults{}
	ev := validateEvent(fs, raw)
	return ev, groups, fs, nil
}

// Admission is an event judged against a verified log it arrived for.
type Admission struct {
	Verified
	// Supersedes is how many events at the end of the log this event
	// replaces: zero when it extends the log, and for a recovery rotation the
	// interactions after the event it follows.
	Supersedes int
	// Repeat is whether the log already holds this event at its place. Nothing
	// changes; Witnessing says what the attachments given with it establish,
	// so a witness's or a further controller's signature can still be taken
	// from it.
	Repeat bool
}

// Admit judges an event that arrives for the identity whose log r is: whether
// it extends the log, repeats an event the log already holds, or is a recovery
// rotation, and refuses anything else.
//
// A recovery rotation is a rotation at a place the log already holds, whose
// prior digest is the event before that place. It replaces the events from its
// place to the end of the log, so it is accepted only where every one of those
// is an interaction: one that would replace an establishment event is refused,
// and the first establishment event seen at a place stands. That is keripy
// 1.3.6's rule for a non-delegated identity. A delegated rotation at a taken
// place is refused here: whether it may supersede turns on its delegator's log,
// which this does not have.
//
// An event at a place past the end of the log is refused as out of order; one
// whose predecessor has not arrived cannot be judged.
func (r *SignedKELResult) Admit(message []byte) (*Admission, error) {
	if len(r.states) == 0 {
		return nil, fmt.Errorf("this result holds no verified log to admit an event to")
	}
	ev, groups, fs, err := readMessage(message)
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, fs.err()
	}
	tip := r.states[len(r.states)-1]

	var prev *KeyState
	supersedes, repeat := 0, false
	switch {
	case ev.SN > tip.sn+1:
		fs.add(FaultSequenceSkip, "the log ends at sequence number %d, so an event at %d "+
			"cannot be judged until the events before it arrive", tip.sn, ev.SN)
		return nil, fs.err()
	case ev.SN == tip.sn+1:
		prev = tip
	default:
		if ev.SN > 0 {
			prev = r.states[ev.SN-1]
		}
		held := r.states[ev.SN]
		switch {
		case held.digest == ev.SAID:
			repeat = true
		case ev.Ilk == "rot" && ev.SN > tip.establishment:
			supersedes = int(tip.sn - ev.SN + 1)
		default:
			fs.add(FaultPlaceTaken, "the log already holds %s (a %s) at sequence number "+
				"%d, and %s", held.digest, held.ilk, ev.SN, whyNotRecovery(ev, tip))
			return nil, fs.err()
		}
	}

	next, w := advance(fs, prev, ev, groups, true)
	if err := fs.err(); err != nil {
		return nil, err
	}
	return &Admission{Verified: Verified{State: next, Witnessing: w},
		Supersedes: supersedes, Repeat: repeat}, nil
}

func whyNotRecovery(ev *Event, tip *KeyState) string {
	switch ev.Ilk {
	case "rot":
		return fmt.Sprintf("a recovery rotation may replace only the interactions after "+
			"the last establishment event, at sequence number %d", tip.establishment)
	case "drt":
		return "whether a delegated rotation may replace it turns on the delegator's " +
			"log, which this does not have"
	default:
		return fmt.Sprintf("only a rotation may replace an event the log holds, and this "+
			"is a %s", ev.Ilk)
	}
}

// State is the key state after the last event of the log.
func (r *SignedKELResult) State() *KeyState {
	if len(r.states) == 0 {
		return nil
	}
	return r.states[len(r.states)-1]
}

// StateAt is the key state after the event at sequence number sn, or nil when
// the log holds no event there.
func (r *SignedKELResult) StateAt(sn uint64) *KeyState {
	if sn >= uint64(len(r.states)) {
		return nil
	}
	return r.states[sn]
}
