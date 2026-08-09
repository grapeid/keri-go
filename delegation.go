package keri

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Delegated events: how one identity brings another into existence and stays
// answerable for it.
//
// Delegation is two halves that must agree. The delegated identity's own events
// name their delegator in `di`; the delegator anchors those events into its own
// key log with a seal. Either half alone proves nothing — a `dip` nobody
// anchored is a claim of authority never granted, and an anchor pointing at a
// `dip` whose bytes differ points at nothing. So these events are matched to the
// reference byte for byte rather than derived from a reading of the spec: the
// delegated identifier IS a digest of its own event, and a single differing byte
// makes it a different identity that the delegator's existing anchor no longer
// covers.
//
// Two event types live here:
//
//   - dip — a delegated inception. An `icp` with `di` appended, and with a
//     different derivation rule (see BuildDelegatedInception).
//   - drt — a delegated rotation. Byte-for-byte an ordinary `rot` except that
//     `t` says "drt". It carries NO `di` (see BuildDelegatedRotation).

// DelegationInput is what building a delegated event is given.
//
// One type covers both `dip` and `drt` because the vectors present them as one
// kind, and because which one is meant is decided by the data rather than by a
// label: an inception has nothing before it, a rotation chains to something.
// Field names match the vector file, which matches the reference
// implementation's parameters.
type DelegationInput struct {
	// Delegator is the identifier that authorises this one. Required for a
	// `dip`, where it is written into `di` and therefore digested into the
	// delegated identifier itself.
	Delegator string `json:"delegator"`

	// Prefix is the delegated identity's own identifier. Absent on a `dip` —
	// that event is what computes it — and required on a `drt`.
	Prefix string `json:"prefix"`

	Keys        []string `json:"keys"`
	NextDigests []string `json:"next_digests"`

	// PriorSAID and SN chain a `drt` to the event before it. Their absence is
	// what marks an input as a delegated INCEPTION; see BuildDelegation.
	PriorSAID string `json:"prior_said"`
	SN        int    `json:"sn"`

	// Thresholds are either a hex count string ("2") or a list of weight
	// strings (["1/2","1/2","1/2"]). Kept as raw JSON so both forms the
	// reference produces survive the trip without this package inventing a type
	// that can only express one of them.
	Isith json.RawMessage `json:"isith"`
	Nsith json.RawMessage `json:"nsith"`

	// A `dip` states its witnesses outright, as any inception does. A `drt`
	// states them as a DELTA against the set the identity already has, which is
	// why it needs the prior set as well as the cuts and adds.
	Witnesses      []string `json:"witnesses"`
	PriorWitnesses []string `json:"prior_witnesses"`
	Cuts           []string `json:"cuts"`
	Adds           []string `json:"adds"`

	// A pointer because absent and zero are different answers: absent means
	// "derive the threshold from the witness count", zero means "no witness
	// need agree", and a plain int could not tell them apart.
	Toad *int `json:"toad"`

	// Seals stay as raw bytes. A seal's own field order is part of the event,
	// and Go marshals a map alphabetically, so any trip through one silently
	// reorders it and changes the identifier.
	Data []json.RawMessage `json:"data"`
}

// dipWire is a delegated inception in the order KERI serialises it.
//
// Field ORDER is protocol, not style: the version string states the length of
// everything after it and the identifier is a digest of the whole thing, so a
// reordered event is a different identity. A struct, never a map — Go marshals a
// struct in declaration order and a map alphabetically.
//
// This is icpWire with `di` appended, and `di` genuinely goes LAST, after the
// seal list. Written out in full rather than embedding icpWire so that the one
// thing a reader needs to check — the order — is visible in one place, and so
// that no promoted MarshalJSON can quietly drop the field that makes this event
// delegated at all.
type dipWire struct {
	V string `json:"v"`
	T string `json:"t"`
	D string `json:"d"`
	I string `json:"i"`
	S string `json:"s"`
	// Thresholds are raw bytes for the reason given on DelegationInput: they
	// are legitimately two different shapes, and they are NEVER JSON numbers.
	KT json.RawMessage   `json:"kt"`
	K  []string          `json:"k"`
	NT json.RawMessage   `json:"nt"`
	N  []string          `json:"n"`
	BT string            `json:"bt"`
	B  []string          `json:"b"`
	C  []string          `json:"c"`
	A  []json.RawMessage `json:"a"`
	// DI names the delegator. Its presence is the whole difference between this
	// identity and one that founded itself, and because it is inside the bytes
	// the identifier digests, the delegator cannot be swapped afterwards
	// without producing a different identity.
	DI string `json:"di"`
}

// MarshalJSON writes the version placeholder at its final width, so the two
// serialisation passes agree on length.
func (w dipWire) MarshalJSON() ([]byte, error) {
	type wire dipWire // avoid recursing into this method
	if w.V == "" {
		w.V = versionString(0)
	}
	return json.Marshal(wire(w))
}

// drtWire is a delegated rotation in the order KERI serialises it.
//
// Identical in shape to rotWire — same fields, same order, and notably NO `di`.
// Declared separately only because `t` differs; see BuildDelegatedRotation for
// why the delegator is not restated here.
type drtWire = rotWire

// BuildDelegation returns the canonical bytes of a delegated event.
//
// Which event is meant is decided from the data, not from a flag: an inception
// is the event that has nothing before it, so an input carrying no prior event
// to chain to is a `dip` and one carrying a prior event is a `drt`. Reading it
// from a label instead would let a caller ask for a rotation at sequence zero,
// or an inception that chains to something, and both are events no peer accepts.
func BuildDelegation(in DelegationInput) ([]byte, error) {
	if in.PriorSAID == "" {
		return BuildDelegatedInception(in)
	}
	return BuildDelegatedRotation(in)
}

// BuildDelegatedInception returns the canonical bytes of a `dip`.
//
// THE DERIVATION RULE, which is the thing worth stating because it is invisible
// from the code and is where this is most easily got wrong:
//
//	A delegated inception is ALWAYS self-addressing, even with a single key.
//
// An ordinary `icp` has two derivation styles and picks by key count: one key
// means BASIC derivation, where the identifier IS the public key and only `d` is
// blanked before digesting; anything else means SELF-ADDRESSING, where `i` and
// `d` are both blanked, one digest is taken, and it fills both. A `dip` does not
// get that choice — it takes the self-addressing path unconditionally, so `i`
// and `d` are equal and both are the digest of the event with both blanked.
//
// Established from the reference implementation rather than assumed. keripy's
// eventing.incept() applies the single-key shortcut inside an `else` branch that
// runs only when no delegator was given:
//
//	if delpre is not None:      # delegated inception with ilk = dip
//	    ked['di'] = delpre
//	else:                       # non delegated
//	    if (code is None or code not in DigDex) and len(keys) == 1:
//	        ked["i"] = keys[0]
//
// With `i` left empty, serdering.SerderKERI.makify() finds it still listed as a
// said field for the `dip` ilk (saids = {'d': 'E', 'i': 'E'}), dummies both, and
// fills both from the single digest. The vector agrees: the `dip` case has
// exactly one key and yet its `i` is an E… digest equal to its `d`, where the
// single-key `icp` case in the same file has `i` equal to its key.
//
// WHY the protocol does it this way, since the rule is otherwise arbitrary: the
// delegated identifier has to commit to its delegator. If a single-key `dip`
// took its identifier from the key, `di` would sit outside the identifier, and
// the same identifier could be presented under a different delegator — the
// authority a delegated identity rests on could be rewritten without changing
// who the identity is. Digesting the whole event, `di` included, makes the
// delegator part of the identity itself.
//
// Getting this wrong is the quiet failure this comment exists to prevent: using
// basic derivation yields a `D…` identifier and a `d` that both look perfectly
// well formed, verify against the event locally, and are rejected by every peer
// and by the delegator's own anchor.
func BuildDelegatedInception(in DelegationInput) ([]byte, error) {
	if in.Delegator == "" {
		return nil, fmt.Errorf("a delegated inception must name its delegator; " +
			"without one it is an ordinary inception claiming an authority nobody granted")
	}
	if len(in.Keys) == 0 {
		return nil, fmt.Errorf("an identity must be founded on at least one key")
	}
	// A prefix cannot be supplied: this event is what computes it, and honouring
	// one would produce an identifier that is not the digest of its own event.
	if in.Prefix != "" && in.Prefix != in.Delegator {
		// Tolerated only when it is genuinely the value this event will
		// produce, which the caller cannot know in advance — so in practice,
		// refused.
		return nil, fmt.Errorf("a delegated inception derives its own identifier and cannot "+
			"be told to use %s", in.Prefix)
	}
	if err := noDuplicates(in.Keys, "signing key"); err != nil {
		return nil, err
	}
	if err := noDuplicates(in.Witnesses, "witness"); err != nil {
		return nil, err
	}

	// Thresholds are rendered by the inception helper rather than re-derived
	// here: a `dip` states its thresholds exactly as an `icp` does, and a second
	// copy of that logic would be a second place for the hexadecimal rule to be
	// got wrong. The floors differ between the two fields for the reason given
	// there — a signing threshold of zero is an identity that need not sign,
	// while a NEXT threshold of zero is the legitimate way to abandon one.
	kt, err := renderThreshold(in.Isith, len(in.Keys), 1, "kt")
	if err != nil {
		return nil, err
	}
	nt, err := renderThreshold(in.Nsith, len(in.NextDigests), 0, "nt")
	if err != nil {
		return nil, err
	}

	toad, err := inceptionToad(in.Toad, len(in.Witnesses))
	if err != nil {
		return nil, err
	}

	blank := strings.Repeat("#", saidPlaceholderLen)
	w := dipWire{
		T: "dip",
		// Both blanked, at exactly the final width, before the single digest is
		// taken. Not one then the other: a second digest taken once `i` is known
		// would cover different bytes and come out different, leaving an event
		// whose identifier is not its own SAID.
		D:  blank,
		I:  blank,
		S:  sequenceNumber(0), // an inception is always the first event
		KT: kt,
		K:  in.Keys,
		NT: nt,
		N:  emptyIfNil(in.NextDigests),
		BT: hexCount(toad),
		B:  emptyIfNil(in.Witnesses),
		// Configuration traits. Nothing here sets any, but the field is not
		// optional: an event missing `c` is a different length and therefore a
		// different identity.
		C:  []string{},
		A:  emptySealsIfNil(in.Data),
		DI: in.Delegator,
	}

	raw, err := serialize(w)
	if err != nil {
		return nil, err
	}
	prefix, err := Blake3SAID(raw)
	if err != nil {
		return nil, fmt.Errorf("could not derive the delegated identifier: %w", err)
	}
	if len(prefix) != saidPlaceholderLen {
		return nil, fmt.Errorf("identifier is %d characters and the placeholder was %d, "+
			"so the event's declared size is now wrong", len(prefix), saidPlaceholderLen)
	}
	w.I, w.D = prefix, prefix
	return serialize(w)
}

// BuildDelegatedRotation returns the canonical bytes of a `drt`.
//
// A `drt` is an ordinary rotation in every respect but one: `t` says "drt". It
// carries the same fields in the same order, chains to the prior event by
// digest, states witnesses as cuts and adds, and derives its SAID by blanking
// `d` alone — `i` is given, so it is not a said field here.
//
// It carries NO `di`. That is worth stating because it looks like an omission
// and is not: the delegator was digested into the delegated identifier at
// inception and therefore cannot change, so restating it on every rotation would
// add bytes that say nothing new and could disagree with the founding event.
// Established the same way as the inception rule — keripy's eventing.deltate()
// is `rotate(..., ilk=Ilks.drt)` and nothing more, rotate() never writes `di`,
// and SerderKERI's field table for `drt` is identical to `rot`. The vector for
// the `drt` case shows no `di` either.
//
// What still differs from a `rot`, and is the reason the ilk exists at all, is
// not in these bytes: acceptance of a `drt` depends on the delegator anchoring
// it, exactly as the `dip` did. A peer treating this identity as delegated will
// refuse a plain `rot` here, and will refuse a `drt` the delegator never
// anchored. Emitting `rot` therefore produces an event that is well formed,
// verifies against itself, and is accepted by nobody.
func BuildDelegatedRotation(in DelegationInput) ([]byte, error) {
	if in.Prefix == "" {
		return nil, fmt.Errorf("a delegated rotation must name the identity it belongs to")
	}
	if in.PriorSAID == "" {
		return nil, fmt.Errorf("a delegated rotation must chain to the event before it")
	}
	// Sequence zero is the inception by definition, so a rotation there would
	// claim to found an identity it also claims already exists.
	if in.SN < 1 {
		return nil, fmt.Errorf("a delegated rotation cannot sit at sequence %d; "+
			"sequence 0 is the delegated inception", in.SN)
	}

	keys := emptyIfNil(in.Keys)
	nexts := emptyIfNil(in.NextDigests)

	// Rendered by the rotation helper rather than re-derived. Same reasoning as
	// the inception half above: one implementation of the hexadecimal and
	// weight rules, not a third copy of it.
	kt, err := rotParseThreshold(in.Isith, max(1, rotCeilDiv(len(keys), 2)))
	if err != nil {
		return nil, fmt.Errorf("current signing threshold: %w", err)
	}
	if kt.size > len(keys) {
		return nil, fmt.Errorf("the signing threshold needs %d keys but the "+
			"rotation presents %d", kt.size, len(keys))
	}
	nt, err := rotParseThreshold(in.Nsith, max(0, rotCeilDiv(len(nexts), 2)))
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

	w := drtWire{
		T:  "drt",
		D:  strings.Repeat("#", saidPlaceholderLen),
		I:  in.Prefix,
		S:  sequenceNumber(in.SN),
		P:  in.PriorSAID,
		KT: kt.value,
		K:  keys,
		NT: nt.value,
		N:  nexts,
		BT: sequenceNumber(toad),
		BR: cuts,
		BA: adds,
		A:  emptySealsIfNil(in.Data),
	}

	// Only `d` is blanked. `i` was fixed by the delegated inception and is
	// carried, not recomputed — recomputing it here would produce a digest of
	// this event rather than of the founding one, which is a different identity
	// wearing the same key history.
	dummy, err := serialize(w)
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
	return serialize(w)
}

// inceptionToad resolves the witness threshold an inceptive event states.
//
// Absent is not zero. With witnesses present and no threshold given, the
// reference derives the smallest threshold that still tolerates the most faults
// a set of that size can survive; defaulting to zero instead would found an
// identity on which no witness need ever agree — the protection silently
// switched off, which is worse than an error.
//
// rotAmple is that derivation, already written for rotations and reused rather
// than copied; it is keripy's ample() and matches it for every set size.
func inceptionToad(toad *int, witnesses int) (int, error) {
	n := 0
	if toad != nil {
		n = *toad
	} else if witnesses > 0 {
		n = rotAmple(witnesses)
	}
	if err := checkToad(n, witnesses); err != nil {
		return 0, err
	}
	return n, nil
}
