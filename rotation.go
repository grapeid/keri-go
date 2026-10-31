package keri

import (
	"encoding/json"
	"fmt"
	"strings"
)

// A rotation event: the thing that makes a KERI identifier survive a key
// compromise. It presents the key the PREVIOUS establishment event committed
// to (pre-rotation), chains to that event by digest, and may in the same
// breath change the signing threshold, add or remove witnesses, and anchor a
// seal.
//
// Every one of those is a place two implementations can differ silently — the
// event still parses, still verifies against itself, and simply describes a
// different future than the one the rest of the world recorded. So this file
// matches the reference byte for byte rather than reading the specification and
// hoping.

// rotWire is a rotation event in the order KERI serialises it.
//
// Field ORDER is load-bearing, not style. The version string states the length
// of everything after it and the identifier is a digest of the whole thing, so
// a reordered event is a different identity. Declared as a struct because Go
// marshals a struct in declaration order and a map alphabetically, and the
// alphabetical form is what made our stored events unreadable to the reference
// implementation for months.
//
// Note what is NOT here: a rotation carries no `c` (configuration traits) —
// those are settled at inception — and it carries witness DELTAS (`br`/`ba`)
// rather than a full witness list. Emitting the full list instead is the
// mistake that produces a rotation no peer will accept, because peers apply the
// delta to the set they already hold.
type rotWire struct {
	V string `json:"v"`
	T string `json:"t"`
	D string `json:"d"`
	I string `json:"i"`
	S string `json:"s"`
	P string `json:"p"`
	// Thresholds are carried as raw JSON because they are legitimately two
	// different shapes — a hex count string ("2") or a list of weight strings
	// (["1/2","1/2","1/2"]) — and pinning them to one Go type would force the
	// other through a conversion that changes the bytes. They are NEVER
	// integers: an implementation that emits 2 rather than "2" disagrees with
	// every peer about who may sign next.
	KT json.RawMessage `json:"kt"`
	K  []string        `json:"k"`
	NT json.RawMessage `json:"nt"`
	N  []string        `json:"n"`
	BT string          `json:"bt"`
	BR []string        `json:"br"`
	BA []string        `json:"ba"`
	// Seals are carried as the bytes they arrived as, never through a map, for
	// the same reason the field order above matters: a seal's own field order
	// is part of the event, and a map would sort it alphabetically.
	A []json.RawMessage `json:"a"`
	// ver is the CESR version this event is being built under. Unexported, so
	// it is never serialised; it exists so the placeholder written on the first
	// pass is the same WIDTH as the version string written on the second. The
	// two encodings differ in width (17 characters against 16), and a
	// placeholder of the wrong width makes the declared size wrong by exactly
	// that difference.
	ver Version
}

// MarshalJSON writes the version placeholder at its final width, so that the
// two serialisation passes agree on length.
func (w rotWire) MarshalJSON() ([]byte, error) {
	type wire rotWire // avoid recursing into this method
	if w.V == "" {
		w.V = placeholderVersionString(ProtocolKERI, w.versionOrDefault())
	}
	return json.Marshal(wire(w))
}

// BuildRotation returns the canonical bytes of a rotation event.
//
// A rotation carries the key the previous event committed to and chains to that
// event by digest. Both are checked by whoever reads the history, so both are
// places this can differ from the reference without anything local noticing.
//
// Whether the presented key was actually pre-committed cannot be decided here —
// it needs the prior event, which building an event is not given. That check
// belongs to validation, and its absence here is why a rotation that looks
// perfectly well formed can still be rejected by a peer.
func BuildRotation(in RotationInput) ([]byte, error) {
	ver, err := resolveVersion(in.Version)
	if err != nil {
		return nil, err
	}
	if in.Prefix == "" {
		return nil, fmt.Errorf("a rotation must name the identity it belongs to")
	}
	if in.PriorSAID == "" {
		return nil, fmt.Errorf("a rotation must chain to the event before it")
	}
	// Sequence zero is inception by definition, so a rotation there would be
	// claiming to found an identity it also claims already exists.
	if in.SN < 1 {
		return nil, fmt.Errorf("a rotation cannot sit at sequence %d; "+
			"sequence 0 is the inception", in.SN)
	}

	keys := in.Keys
	if keys == nil {
		keys = []string{}
	}
	nexts := in.NextDigests
	if nexts == nil {
		nexts = []string{}
	}

	// The current threshold defaults to a simple majority of the keys
	// presented. The next threshold may legitimately be zero — that is how an
	// identity is abandoned, by committing to no future keys at all — which is
	// why the two defaults have different floors.
	kt, err := parseThresholdValue(in.Isith, max(1, ceilDiv(len(keys), 2)))
	if err != nil {
		return nil, fmt.Errorf("current signing threshold: %w", err)
	}
	if kt.size > len(keys) {
		return nil, fmt.Errorf("the signing threshold needs %d keys but the "+
			"rotation presents %d", kt.size, len(keys))
	}
	nt, err := parseThresholdValue(in.Nsith, max(0, ceilDiv(len(nexts), 2)))
	if err != nil {
		return nil, fmt.Errorf("next signing threshold: %w", err)
	}
	if nt.size > len(nexts) {
		return nil, fmt.Errorf("the next signing threshold needs %d keys but the "+
			"rotation commits to %d", nt.size, len(nexts))
	}

	cuts, adds, toad, err := rotWitnesses(in.PriorWitnesses, in.Cuts, in.Adds, in.Toad)
	if err != nil {
		return nil, err
	}

	seals := in.Data
	if seals == nil {
		seals = []json.RawMessage{}
	}

	w := rotWire{
		ver: ver,
		T:   "rot",
		D:   strings.Repeat("#", saidPlaceholderLen),
		I:   in.Prefix,
		S:   sequenceNumber(in.SN),
		P:   in.PriorSAID,
		KT:  kt.value,
		K:   keys,
		NT:  nt.value,
		N:   nexts,
		BT:  sequenceNumber(toad),
		BR:  cuts,
		BA:  adds,
		A:   seals,
	}

	// First pass: the event with its identifier blanked to placeholder
	// characters of exactly the final width. The digest is taken over these
	// bytes — not over the event with the field missing, and not with a
	// placeholder of some other width, either of which yields an identifier
	// nothing else in the world agrees with.
	dummy, err := serialize(w, ProtocolKERI, ver)
	if err != nil {
		return nil, err
	}
	said, err := Blake3SAID(dummy)
	if err != nil {
		return nil, fmt.Errorf("could not compute the event's identifier: %w", err)
	}
	if len(said) != saidPlaceholderLen {
		return nil, fmt.Errorf("identifier is %d characters and the placeholder was %d, "+
			"so the event's declared size is now wrong", len(said), saidPlaceholderLen)
	}

	w.D = said
	return serialize(w, ProtocolKERI, ver)
}

// rotWitnesses resolves the witness delta and the witness threshold.
//
// Cuts and adds are emitted exactly as given rather than being recomputed from
// a resulting set, because they ARE the event: a peer applies them to the
// witness set it already holds. The checks here are the reference
// implementation's, and they exist because each of these mistakes produces a
// rotation that is internally consistent and still unusable — cutting a witness
// the identity never had, adding one it already has, or naming a threshold
// larger than the witnesses that will remain.
func rotWitnesses(prior, cuts, adds []string, toad *int) ([]string, []string, int, error) {
	if cuts == nil {
		cuts = []string{}
	}
	if adds == nil {
		adds = []string{}
	}
	priorSet, err := rotSet(prior)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("the prior witness list %w", err)
	}
	cutSet, err := rotSet(cuts)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("the witnesses to remove %w", err)
	}
	addSet, err := rotSet(adds)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("the witnesses to add %w", err)
	}
	for w := range cutSet {
		if !priorSet[w] {
			return nil, nil, 0, fmt.Errorf("cannot remove witness %s: the identity "+
				"does not have it", w)
		}
	}
	for w := range addSet {
		if priorSet[w] {
			return nil, nil, 0, fmt.Errorf("cannot add witness %s: the identity "+
				"already has it", w)
		}
		if cutSet[w] {
			return nil, nil, 0, fmt.Errorf("witness %s is both removed and added", w)
		}
	}

	remaining := len(prior) - len(cuts) + len(adds)

	n := toad
	if n == nil {
		// No threshold stated: the reference derives one that still tolerates
		// the largest number of faulty witnesses the set can survive. Derived
		// rather than defaulted to zero, because a zero threshold on a
		// witnessed identity means "no witness need agree", which is the
		// protection silently switched off.
		derived := 0
		if remaining > 0 {
			derived = ample(remaining)
		}
		n = &derived
	}
	if remaining == 0 {
		if *n != 0 {
			return nil, nil, 0, fmt.Errorf("witness threshold %d with no witnesses "+
				"can never be met", *n)
		}
	} else if *n < 1 || *n > remaining {
		return nil, nil, 0, fmt.Errorf("witness threshold %d is out of range for the "+
			"%d witnesses this rotation leaves", *n, remaining)
	}
	return cuts, adds, *n, nil
}

// rotSet builds a membership set and rejects duplicates.
//
// A duplicate is rejected rather than collapsed: "add this witness twice" is
// not a request with an obvious meaning, and quietly making it mean "once"
// leaves the caller believing something the event does not say.
//
// Every entry must be a canonical non-transferable identifier. Membership is
// then tested by text, which is sound only because each key has exactly one
// canonical string; the duplicate check compares keys regardless.
func rotSet(items []string) (map[string]bool, error) {
	if err := noDuplicateWitnesses(items, "witness"); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(items))
	for _, it := range items {
		set[it] = true
	}
	return set, nil
}

// versionOrDefault is the version this event is built under, falling back to
// the package default when the caller did not set one.
func (w rotWire) versionOrDefault() Version {
	if w.ver == (Version{}) {
		return DefaultVersion
	}
	return w.ver
}
