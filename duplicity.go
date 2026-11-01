package keri

import (
	"fmt"
	"sort"
	"sync"
)

// Noticing that an identity has signed two different histories.
//
// Every other check in this package asks whether ONE key log holds together.
// Duplicity is the question that cannot be answered that way: two logs, each
// internally perfect, each correctly signed, disagreeing about what happened at
// the same point. That is what a stolen key produces, and what a controller
// producing a second history for a second audience produces. Neither is
// detectable from either log alone — only from having seen both.
//
// So this is a memory rather than a validator. It records what it has seen and
// reports the moment two accounts of the same position disagree.
//
// One thing it will not do: treat an unverified event as evidence. If an
// unsigned or wrongly signed event could raise duplicity, then anyone able to
// send bytes could brand any identity as duplicitous, and the alarm becomes a
// weapon rather than a protection. An event that does not verify is discarded
// as noise, which is what it is.

// Duplicity is proof that an identity produced two different events at one
// point in its history.
type Duplicity struct {
	// Identifier is the identity that signed both.
	Identifier string
	// SN is the position they disagree about.
	SN uint64
	// Seen is the event recorded first.
	Seen string
	// Conflicting is the event that disagrees with it.
	Conflicting string
	// SeenRaw and ConflictingRaw are both events, kept because the evidence is
	// the pair of signed events and not the assertion that they differ. Anyone
	// told about this must be able to check it rather than take it on trust.
	SeenRaw        []byte
	ConflictingRaw []byte
}

func (d *Duplicity) Error() string {
	return fmt.Sprintf("%s has two different events at sequence number %d: %s and %s",
		d.Identifier, d.SN, d.Seen, d.Conflicting)
}

// Watcher remembers key events and reports duplicity.
//
// It is what an agent uses to watch itself, and to cross-check a peer. The same
// memory answers both: an identity contradicting itself looks identical whether
// the identity is yours or somebody else's.
type Watcher struct {
	mu sync.Mutex
	// seen maps an identifier and sequence number to the event recorded there.
	seen map[string]map[uint64][]byte
	// verify decides whether an event counts as evidence.
	verify func(event []byte) error
	// keys is the key state each identity has established, so that an event
	// carrying no keys of its own can still be checked. Without this a watcher
	// cannot verify an interaction at all — and an interaction is what anchors
	// delegations and credential issuances.
	keys      map[string][]string
	threshold map[string]*parsedThreshold
	// commitments is, per identity, the next-key commitment each first-seen
	// establishment event made, in sequence order. A rotation must open
	// enough of the one before it; without this a watcher would record as
	// evidence a rotation signed by keys nobody committed to.
	commitments map[string][]commitment
}

// commitment is what an establishment event at sn commits the next rotation
// to.
type commitment struct {
	sn     uint64
	next   []string
	nextTh *parsedThreshold
}

// NewWatcher returns a watcher that accepts only events whose signatures it can
// check.
//
// verifySigned is given the event WITH its attachments and must return an error
// if it does not verify. Passing nil means structural validation only, which is
// weaker and appropriate only where the transport already authenticated the
// sender — state it deliberately rather than reaching for it by default.
func NewWatcher(verifySigned func(message []byte) error) *Watcher {
	if verifySigned == nil {
		verifySigned = func(message []byte) error {
			raw, _, err := splitStream(message)
			if err != nil {
				return err
			}
			_, err = ParseEvent(raw)
			return err
		}
	}
	return &Watcher{
		seen:        map[string]map[uint64][]byte{},
		keys:        map[string][]string{},
		threshold:   map[string]*parsedThreshold{},
		commitments: map[string][]commitment{},
		verify:      verifySigned,
	}
}

// NewSignatureCheckingWatcher returns a watcher that verifies every event it is
// offered before recording it.
//
// An establishment event is checked against the keys it declares, which are not
// self-asserted because a rotation must present keys the previous event
// committed to. An event carrying no keys — an interaction — is checked against
// the key state this watcher has already seen that identity establish, and is
// REFUSED if none is known.
//
// That refusal matters. ValidateStream verifies signatures only on
// establishment events, because an interaction carries no keys for it to check
// against; handed one it reports no fault, which reads exactly like a pass. A
// watcher relying on that would accept any interaction anyone cared to invent,
// and the first version of this file did, which is how the gap was found.
func NewSignatureCheckingWatcher() *Watcher {
	w := NewWatcher(nil)
	w.verify = w.verifyAgainstEstablishedKeys
	return w
}

// verifyAgainstEstablishedKeys checks an event against the key state its
// identity has established, falling back to the event's own keys when it
// declares them.
func (w *Watcher) verifyAgainstEstablishedKeys(message []byte) error {
	raw, attached, err := splitStream(message)
	if err != nil {
		return err
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		return err
	}
	if ev.Ilk == "rot" || ev.Ilk == "drt" {
		return w.verifyRotation(ev, message)
	}
	if ev.Establishment() {
		// An inception declares its own keys and ValidateStream checks them.
		return ValidateStream(message)
	}

	w.mu.Lock()
	keys := w.keys[ev.Identifier]
	threshold := w.threshold[ev.Identifier]
	w.mu.Unlock()

	if len(keys) == 0 {
		return fmt.Errorf("%s has established no keys this watcher has seen, so an "+
			"event carrying none of its own cannot be checked; refusing to record it "+
			"as evidence", ev.Identifier)
	}
	groups, err := parseAttachments(attached)
	if err != nil {
		return err
	}
	fs := &faults{}
	verifyAgainstKeyState(fs, ev, groups, keys, threshold)
	return fs.err()
}

// verifyRotation checks a rotation's own signatures against its keys and kt,
// and that the keys which signed open enough of the commitment made by the
// last establishment event this watcher saw before it: the same rule
// ValidateSignedKEL applies. A rotation whose prior commitment the watcher
// has not seen is refused, as an interaction with no known keys is: anyone can
// sign a rotation to keys of their own, and only the prior commitment says
// whether those keys had the authority.
func (w *Watcher) verifyRotation(ev *Event, message []byte) error {
	if err := ValidateStream(message); err != nil {
		return err
	}
	w.mu.Lock()
	var prior *commitment
	for i, c := range w.commitments[ev.Identifier] {
		if c.sn < ev.SN {
			prior = &w.commitments[ev.Identifier][i]
		}
	}
	var next []string
	var nextTh *parsedThreshold
	if prior != nil {
		next, nextTh = prior.next, prior.nextTh
	}
	w.mu.Unlock()

	if prior == nil {
		return fmt.Errorf("this watcher has seen no establishment event of %s before sn %d, "+
			"so whether the keys that signed this rotation were committed to cannot be "+
			"checked; refusing to record it as evidence", ev.Identifier, ev.SN)
	}
	_, attached, err := splitStream(message)
	if err != nil {
		return err
	}
	groups, err := parseAttachments(attached)
	if err != nil {
		return err
	}
	fs := &faults{}
	fs.at(fmt.Sprintf("%s at sn %d", ev.Ilk, ev.SN))
	verified := verifyAgainstKeyState(fs, ev, groups, ev.Keys, ev.SigThreshold)
	checkPriorNextOpened(fs, ev, verified, next, nextTh)
	return fs.err()
}

// Observe records an event and reports duplicity if it contradicts one already
// seen.
//
// Returning the same event twice is not duplicity and not an error — an agent
// receives the same event from several sources routinely, and treating a repeat
// as a conflict would make the alarm useless.
func (w *Watcher) Observe(message []byte) (*Duplicity, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("there is no event to observe")
	}
	if err := w.verify(message); err != nil {
		// Discarded rather than recorded. An event that does not verify is not
		// evidence of anything, and admitting it would let anyone manufacture
		// duplicity against an identity they do not control.
		return nil, fmt.Errorf("refusing to record an event that does not verify: %w", err)
	}
	raw, _, err := splitStream(message)
	if err != nil {
		return nil, err
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	byPosition, known := w.seen[ev.Identifier]
	if !known {
		byPosition = map[uint64][]byte{}
		w.seen[ev.Identifier] = byPosition
	}
	previous, occupied := byPosition[ev.SN]
	if !occupied {
		byPosition[ev.SN] = append([]byte(nil), message...)
		w.recordKeyState(ev)
		return nil, nil
	}

	previousRaw, _, err := splitStream(previous)
	if err != nil {
		return nil, err
	}
	previousEv, err := ParseEvent(previousRaw)
	if err != nil {
		return nil, err
	}
	if previousEv.SAID == ev.SAID {
		// The same event again.
		return nil, nil
	}

	return &Duplicity{
		Identifier:     ev.Identifier,
		SN:             ev.SN,
		Seen:           previousEv.SAID,
		Conflicting:    ev.SAID,
		SeenRaw:        previous,
		ConflictingRaw: append([]byte(nil), message...),
	}, nil
}

// ObserveLog records a whole key log, reporting the first duplicity found.
//
// The events already recorded are kept when one is found, because the point of
// noticing is to have the evidence, not to discard the history that produced it.
func (w *Watcher) ObserveLog(messages [][]byte) (*Duplicity, error) {
	for i, m := range messages {
		dup, err := w.Observe(m)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		if dup != nil {
			return dup, nil
		}
	}
	return nil, nil
}

// Known reports the identifiers this watcher has recorded, sorted.
func (w *Watcher) Known() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.seen))
	for id := range w.seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Height is the highest sequence number recorded for an identity, and whether
// anything is recorded at all.
func (w *Watcher) Height(identifier string) (uint64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	byPosition, known := w.seen[identifier]
	if !known || len(byPosition) == 0 {
		return 0, false
	}
	var highest uint64
	for sn := range byPosition {
		if sn > highest {
			highest = sn
		}
	}
	return highest, true
}

// recordKeyState remembers what an establishment event puts in force, so that
// later events carrying no keys can be checked against it.
//
// Called with the lock held.
func (w *Watcher) recordKeyState(ev *Event) {
	if !ev.Establishment() || len(ev.Keys) == 0 {
		return
	}
	w.keys[ev.Identifier] = ev.Keys
	w.threshold[ev.Identifier] = ev.SigThreshold
	// Kept in sequence order, so the commitment before a rotation is the last
	// one with a lower sequence number.
	list := append(w.commitments[ev.Identifier], commitment{
		sn: ev.SN, next: ev.NextDigest, nextTh: ev.NextThreshold})
	sort.SliceStable(list, func(i, j int) bool { return list[i].sn < list[j].sn })
	w.commitments[ev.Identifier] = list
}
