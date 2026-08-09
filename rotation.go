package keri

import (
	"encoding/json"
	"fmt"
	"strconv"
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
}

// MarshalJSON writes the version placeholder at its final width, so that the
// two serialisation passes agree on length.
func (w rotWire) MarshalJSON() ([]byte, error) {
	type wire rotWire // avoid recursing into this method
	if w.V == "" {
		w.V = versionString(0)
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

	seals := in.Data
	if seals == nil {
		seals = []json.RawMessage{}
	}

	w := rotWire{
		T:  "rot",
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
		A:  seals,
	}

	// First pass: the event with its identifier blanked to placeholder
	// characters of exactly the final width. The digest is taken over these
	// bytes — not over the event with the field missing, and not with a
	// placeholder of some other width, either of which yields an identifier
	// nothing else in the world agrees with.
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
			derived = rotAmple(remaining)
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
func rotSet(items []string) (map[string]bool, error) {
	set := make(map[string]bool, len(items))
	for _, it := range items {
		if set[it] {
			return nil, fmt.Errorf("names %s twice", it)
		}
		set[it] = true
	}
	return set, nil
}

// rotThreshold is a signing threshold as it will appear in the event, plus the
// fewest keys that could satisfy it.
//
// The size is kept because it is the only check available at build time: a
// threshold of 3 over 2 keys can never be met, and an identity that commits to
// one has locked itself out permanently.
type rotThreshold struct {
	value json.RawMessage
	size  int
}

// rotParseThreshold renders a threshold the way the reference does.
//
// Three input shapes are accepted because three are produced: absent (take the
// default), a count, and a list of fractional weights. Two details here are
// easy to get wrong and impossible to notice locally:
//
//   - A count string is HEXADECIMAL, in and out. "a" is ten, not an error, and
//     ten is written "a", not "10". A decimal reading agrees with hex for every
//     threshold below ten, which is exactly why it survives testing.
//   - The output is always a STRING (or a list of strings), never a JSON
//     number, even though a count is conceptually a number.
//
// Weights are normalised as rationals, so "2/4" is written "1/2" and "1/1" is
// written "1". Two events that differ only in how a weight was spelled would
// otherwise have different identifiers.
func rotParseThreshold(raw json.RawMessage, def int) (rotThreshold, error) {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed == "null" {
		return rotNumericThreshold(def)
	}

	switch trimmed[0] {
	case '[':
		return rotWeightedThreshold(trimmed)
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return rotThreshold{}, err
		}
		// A weighted threshold arriving as a JSON string is how the reference
		// accepts one from a command line or config file. Unwrapped here rather
		// than rejected, so the same vector data reads the same either way.
		if strings.Contains(s, "[") {
			return rotWeightedThreshold(s)
		}
		n, err := strconv.ParseInt(s, 16, 32)
		if err != nil {
			return rotThreshold{}, fmt.Errorf("%q is not a hexadecimal threshold", s)
		}
		return rotNumericThreshold(int(n))
	default:
		// A bare JSON number. Accepted on the way in — it is an unambiguous
		// count — but written back out as a hex string, which is the only form
		// a peer will read.
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return rotThreshold{}, fmt.Errorf("%q is not a threshold", trimmed)
		}
		i, err := strconv.Atoi(n.String())
		if err != nil {
			return rotThreshold{}, fmt.Errorf("threshold %s is not a whole number", n)
		}
		return rotNumericThreshold(i)
	}
}

func rotNumericThreshold(n int) (rotThreshold, error) {
	if n < 0 {
		return rotThreshold{}, fmt.Errorf("threshold %d is negative", n)
	}
	// Encoded by hand rather than through json.Marshal of a string: the value
	// is a hex count and this keeps the one place it is rendered next to the
	// one place it is parsed.
	v, err := json.Marshal(strconv.FormatInt(int64(n), 16))
	if err != nil {
		return rotThreshold{}, err
	}
	// A count threshold says nothing about how many keys exist, so the fewest
	// keys that can satisfy it is the count itself.
	return rotThreshold{value: v, size: n}, nil
}

// rotWeightedThreshold renders fractional weights.
//
// A weighted threshold is one or more clauses of weights; the signatures
// satisfy it when every clause's weights sum to at least one. A single clause
// is written flat (["1/2","1/2","1/2"]) rather than nested, which is the form
// the reference emits and therefore the only form that digests the same.
func rotWeightedThreshold(js string) (rotThreshold, error) {
	var nested [][]string
	if err := json.Unmarshal([]byte(js), &nested); err != nil {
		var flat []string
		if err2 := json.Unmarshal([]byte(js), &flat); err2 != nil {
			return rotThreshold{}, fmt.Errorf("%s is not a list of weights: %w", js, err)
		}
		nested = [][]string{flat}
	}
	if len(nested) == 0 {
		return rotThreshold{}, fmt.Errorf("a weighted threshold with no weights "+
			"can never be met: %s", js)
	}

	out := make([][]string, 0, len(nested))
	size := 0
	for _, clause := range nested {
		if len(clause) == 0 {
			return rotThreshold{}, fmt.Errorf("a threshold clause with no weights "+
				"can never be met: %s", js)
		}
		rendered := make([]string, 0, len(clause))
		sumNum, sumDen := 0, 1
		for _, w := range clause {
			num, den, err := rotWeight(w)
			if err != nil {
				return rotThreshold{}, err
			}
			sumNum, sumDen = sumNum*den+num*sumDen, sumDen*den
			g := rotGCD(sumNum, sumDen)
			sumNum, sumDen = sumNum/g, sumDen/g
			if num == 0 || num == den {
				rendered = append(rendered, strconv.Itoa(num/den))
			} else {
				rendered = append(rendered, fmt.Sprintf("%d/%d", num, den))
			}
		}
		// The reference refuses a clause that cannot reach one, because such a
		// threshold is unsatisfiable no matter who signs.
		if sumNum < sumDen {
			return rotThreshold{}, fmt.Errorf("threshold clause %v sums to less than "+
				"1, so no set of signatures can satisfy it", clause)
		}
		size += len(clause)
		out = append(out, rendered)
	}

	var value any = out
	if len(out) == 1 {
		value = out[0]
	}
	v, err := json.Marshal(value)
	if err != nil {
		return rotThreshold{}, err
	}
	// A weight sits against a specific key by position, so a weighted threshold
	// states exactly how many keys there must be.
	return rotThreshold{value: v, size: size}, nil
}

// rotWeight parses one weight as an exact rational.
//
// Exact rather than floating point on purpose: weights are compared against 1
// and summed, and a float sum of thirds does not reach 1. Only whole numbers
// and n/d ratios are accepted — a decimal like "0.5" is refused rather than
// rounded, matching the reference, because two spellings of the same weight
// would otherwise digest differently.
func rotWeight(w string) (num, den int, err error) {
	if i := strings.IndexByte(w, '/'); i >= 0 {
		num, err = strconv.Atoi(w[:i])
		if err != nil {
			return 0, 0, fmt.Errorf("%q is not a weight: %w", w, err)
		}
		den, err = strconv.Atoi(w[i+1:])
		if err != nil {
			return 0, 0, fmt.Errorf("%q is not a weight: %w", w, err)
		}
		if den <= 0 {
			return 0, 0, fmt.Errorf("%q is not a weight: denominator must be positive", w)
		}
	} else {
		num, err = strconv.Atoi(w)
		if err != nil {
			return 0, 0, fmt.Errorf("%q is not a weight: %w", w, err)
		}
		den = 1
	}
	if num < 0 || num > den {
		return 0, 0, fmt.Errorf("weight %q is outside 0..1", w)
	}
	g := rotGCD(num, den)
	return num / g, den / g, nil
}

func rotGCD(a, b int) int {
	if a < 0 {
		a = -a
	}
	for b != 0 {
		a, b = b, a%b
	}
	if a == 0 {
		return 1
	}
	return a
}

// rotAmple returns the witness threshold to use when a rotation does not state
// one.
//
// It is the smallest threshold that still tolerates the most faults a set of
// this size can survive — the reference's derivation, reproduced rather than
// approximated. A simple majority looks close enough and is not: it accepts
// histories the rest of the network will reject, and only once real witnesses
// disagree.
func rotAmple(n int) int {
	if n < 1 {
		return 0
	}
	// The most and the least faults tolerable subject to n >= 3f+1; the
	// resulting thresholds are compared and the weaker one taken.
	least := max(1, (n-1)/3)
	most := max(1, rotCeilDiv(n-1, 3))
	return min(n, rotCeilDiv(n+least+1, 2), rotCeilDiv(n+most+1, 2))
}

// rotCeilDiv divides and rounds up, for non-negative inputs.
func rotCeilDiv(a, b int) int {
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}
