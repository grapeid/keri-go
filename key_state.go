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

	// delegated is whether the identity was founded by a delegated inception,
	// which decides the only kind of rotation it may make.
	delegated bool
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

// Delegated is whether the identity was founded by a delegated inception.
func (s *KeyState) Delegated() bool { return s.delegated }

// step is what advance found for one event.
type step struct {
	state      *KeyState
	witnessing EventWitnessing
	// signatures are the controller signatures that verified, as attached.
	signatures []string
}

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
	signed bool) step {

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
		st.delegated = ev.Ilk == "dip"
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
	// keripy 1.3.6 refuses a plain rotation of a delegated identity, which
	// would take it over without its delegator's approval. A delegated
	// rotation of an identity nobody delegated is refused too, which keripy
	// leaves to its delegation check: there is no delegator to approve it.
	if prev != nil && ev.Ilk == "rot" && prev.delegated {
		fs.add(FaultMalformed, "the identity was founded by a delegated inception, so it "+
			"rotates only by a delegated rotation its delegator approves, and this is a rot")
	}
	if prev != nil && ev.Ilk == "drt" && !prev.delegated {
		fs.add(FaultMalformed, "the identity was not founded by a delegated inception, so "+
			"no delegator can approve a delegated rotation of it")
	}
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

	if !signed {
		return step{state: st}
	}
	// An establishment event's own keys are the right thing to check its
	// signatures against. What makes them more than self-asserted, for a
	// rotation, is that the keys which signed open enough of the previous
	// commitment.
	w := countWitnessSignatures(ev, groups, st.witnesses, st.toad)
	if len(st.keys) == 0 {
		fs.add(FaultMalformed, "the %s at sn %d has no key state to check against, "+
			"because no establishment event preceded it", ev.Ilk, ev.SN)
		return step{state: st, witnessing: w}
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
	return step{state: st, witnessing: w, signatures: signatureTexts(verified)}
}

func signatureTexts(sigs []indexedSig) []string {
	out := make([]string, 0, len(sigs))
	for _, sig := range sigs {
		out = append(out, sig.QB64)
	}
	return out
}

// Verified is one event verified against the key state it follows.
type Verified struct {
	// State is the key state after the event.
	State *KeyState
	// Witnessing is what the event's witness-indexed signatures establish.
	// It is reported and not enforced, as in ValidateSignedKEL.
	Witnessing EventWitnessing
	// Signatures are the attached controller signatures that verified, each
	// once, as attached. One that did not verify is not among them.
	Signatures []string
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
	got := advance(fs, state, ev, groups, true)
	if err := fs.err(); err != nil {
		return nil, err
	}
	return &Verified{State: got.state, Witnessing: got.witnessing,
		Signatures: got.signatures}, nil
}

// readMessage splits an event from its attachments and checks what can be
// decided from the event alone. ev is nil when the bytes are not an event, and
// the reason is in fs.
func readMessage(message []byte) (*Event, []attachment, *faults, error) {
	raw, groups, err := splitMessage(message)
	if err != nil {
		return nil, nil, nil, err
	}
	fs := &faults{}
	ev := validateEvent(fs, raw)
	return ev, groups, fs, nil
}

// thresholdCopy is a copy of t for a result's Threshold, so a caller writing
// through it cannot change the threshold a state verifies against. Its parts
// are unexported, so only the struct itself can be written.
func thresholdCopy(t *parsedThreshold) *parsedThreshold {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// splitMessage splits an event from its attachments, as it travels.
func splitMessage(message []byte) ([]byte, []attachment, error) {
	raw, attached, err := splitStream(message)
	if err != nil {
		return nil, nil, fmt.Errorf("not an event with attachments: %w", err)
	}
	groups, err := parseAttachments(attached)
	if err != nil {
		return nil, nil, fmt.Errorf("unreadable attachments: %w", err)
	}
	return raw, groups, nil
}

// Admission is an event judged against a verified log it arrived for.
type Admission struct {
	Verified
	// Supersedes is how many events at the end of the log this event
	// replaces: zero when it extends the log, and for a recovery rotation the
	// interactions after the event it follows.
	Supersedes int
	// Repeat is whether the log already holds this event at its place.
	// Nothing about the log changes. Signatures and Witnessing say which of
	// the signatures given with it verify, so a late witness signature or a
	// further controller signature can be kept; State is the state at the
	// event's own place, which for a repeat of an earlier event is not the end
	// of the log.
	Repeat bool
	// Log is the verified log with this event admitted: extended, with the
	// superseded interactions replaced, or unchanged for a repeat. Admit it
	// the next event, rather than verifying the whole log again.
	Log *SignedKELResult
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
// place is refused here, where keripy may accept one under its delegation
// rules: whether it may supersede turns on its delegator's log, which this does
// not have.
//
// A repeat is admitted when at least one controller or witness signature given
// with it verifies against the key state and witnesses at its place, as keripy
// 1.3.6 logs a duplicate: a repeat need not meet the signing threshold again,
// since the log already holds the event, and that is how late witness
// signatures arrive. The witnesses that signed it are counted in Log. One with
// no signature that verifies is refused, and so is one carrying a controller
// signature that names a place outside the key list, as keripy refuses it.
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

	switch {
	case ev.SN > tip.sn+1:
		fs.add(FaultSequenceSkip, "the log ends at sequence number %d, so an event at %d "+
			"cannot be judged until the events before it arrive", tip.sn, ev.SN)
		return nil, fs.err()
	case ev.SN == tip.sn+1:
		return r.admitAt(fs, ev, groups, 0)
	}
	held := r.states[ev.SN]
	switch {
	case held.digest == ev.SAID:
		return r.repeat(fs, ev, groups, held)
	case ev.Ilk == "rot" && ev.SN > tip.establishment:
		return r.admitAt(fs, ev, groups, int(tip.sn-ev.SN+1))
	default:
		fs.add(FaultPlaceTaken, "the log already holds %s (a %s) at sequence number "+
			"%d, and %s", held.digest, held.ilk, ev.SN, whyNotRecovery(ev, tip))
		return nil, fs.err()
	}
}

// admitAt verifies ev after the event before its place, replacing the last
// supersedes events of the log.
func (r *SignedKELResult) admitAt(fs *faults, ev *Event, groups []attachment,
	supersedes int) (*Admission, error) {

	var prev *KeyState
	if ev.SN > 0 {
		prev = r.states[ev.SN-1]
	}
	got := advance(fs, prev, ev, groups, true)
	if err := fs.err(); err != nil {
		return nil, err
	}
	keep := len(r.states) - supersedes
	log := &SignedKELResult{
		Identifier: r.Identifier,
		Keys:       got.state.Keys(),
		Threshold:  thresholdCopy(got.state.threshold),
		Events:     keep + 1,
		Witnessing: append(append([]EventWitnessing(nil), r.Witnessing[:keep]...),
			got.witnessing),
		states: append(append([]*KeyState(nil), r.states[:keep]...), got.state),
	}
	return &Admission{
		Verified: Verified{State: got.state, Witnessing: got.witnessing,
			Signatures: got.signatures},
		Supersedes: supersedes, Log: log,
	}, nil
}

// repeat judges the signatures given with an event the log already holds.
func (r *SignedKELResult) repeat(fs *faults, ev *Event, groups []attachment,
	held *KeyState) (*Admission, error) {

	verified, _ := verifyControllerSignatures(fs, ev, groups, held.keys)
	w := countWitnessSignatures(ev, groups, held.witnesses, held.toad)
	if err := fs.err(); err != nil {
		return nil, err
	}
	if len(verified) == 0 && len(w.Signed) == 0 {
		fs.add(FaultThresholdNotMet, "the log holds this event, and no controller or "+
			"witness signature given with it again verifies, so it adds nothing")
		return nil, fs.err()
	}
	return &Admission{
		Verified: Verified{State: held, Witnessing: w,
			Signatures: signatureTexts(verified)},
		Repeat: true, Log: r.withWitnesses(held.sn, w),
	}, nil
}

// withWitnesses is r with the witnesses that signed w's event again counted
// for it too, each witness once, so a log collecting late witness signatures
// becomes fully witnessed.
func (r *SignedKELResult) withWitnesses(sn uint64, w EventWitnessing) *SignedKELResult {
	was := r.Witnessing[sn]
	signed := make(map[string]bool, len(was.Signed)+len(w.Signed))
	for _, name := range append(append([]string(nil), was.Signed...), w.Signed...) {
		signed[name] = true
	}
	merged := was
	merged.Signed = nil
	for _, name := range was.Witnesses {
		if signed[name] {
			merged.Signed = append(merged.Signed, name)
		}
	}
	merged.Met = uint64(len(merged.Signed)) >= merged.Threshold
	out := *r
	out.Keys = append([]string(nil), r.Keys...)
	out.Witnessing = append([]EventWitnessing(nil), r.Witnessing...)
	out.Witnessing[sn] = merged
	return &out
}

func whyNotRecovery(ev *Event, tip *KeyState) string {
	switch ev.Ilk {
	case "rot":
		return fmt.Sprintf("a recovery rotation may replace only the interactions after "+
			"the last establishment event, at sequence number %d", tip.establishment)
	case "drt":
		return "whether a delegated rotation may replace it turns on the delegator's " +
			"log, which this does not have; keripy may accept one under its delegation " +
			"rules, so this is not by itself duplicity"
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
