package keri

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// Thresholds: how many of an identity's keys must sign, and how many of its
// witnesses must agree.
//
// One reader, one renderer and one satisfaction rule, used by every event kind
// and by every check. Building an event, validating one, and answering whether a
// set of signatures is enough all go through the same parsed form below, so they
// cannot disagree with each other about what a threshold means.
//
// Two details are easy to get wrong and impossible to notice locally:
//
//   - A count is HEXADECIMAL, in and out. "a" is ten, and ten is written "a".
//     A decimal reading agrees with hex for every threshold below ten, which is
//     exactly why it survives a test suite and fails in the field.
//   - Weights are exact rationals reduced to lowest terms, so "2/4" is written
//     "1/2" and "1/1" is written "1". Float arithmetic cannot be used: three
//     thirds do not sum to 1 in binary floating point, and the clause would be
//     wrongly rejected.
//
// The weighted form is read exactly as keripy 1.3.6's Tholder reads it. A
// threshold is one or more clauses, and every clause must be met. A clause is a
// list of elements, each either a bare weight belonging to one key, or a
// weighted set: a one-entry map {"w": [weights...]} whose weights belong to
// consecutive keys and which contributes w to its clause when its own weights
// sum to at least one. So
//
//	[{"1/2": ["1", "1"]}, {"1/2": ["1", "1"]}, {"1/2": ["1", "1"]}]
//
// is six keys in three pairs, met by any key of any two pairs. A list of lists
// is several clauses; a list of weights and sets is one clause, and a single
// clause is written flat.

// parsedThreshold is a signing threshold: either a count of signatures, or
// weighted clauses.
type parsedThreshold struct {
	weighted bool
	count    uint64
	clauses  [][]thresholdElement
}

// thresholdElement is one entry of a weighted clause.
type thresholdElement struct {
	// weight is what this element contributes to its clause when it is met.
	weight *big.Rat
	// set is nil for a bare weight, which belongs to one key and is met when
	// that key signs. Otherwise it is the weights of a nested set, one per key,
	// and the element is met when the signed ones sum to at least one.
	set []*big.Rat
}

// keys is how many consecutive keys this element weighs.
func (e thresholdElement) keys() int {
	if e.set == nil {
		return 1
	}
	return len(e.set)
}

var ratOne = big.NewRat(1, 1)

// parseThreshold reads a kt or nt value as it appears in an event.
//
// A count is a string of canonical lowercase hexadecimal. Anything else must be
// a list of weights. What it does NOT check is whether the threshold can ever
// be met — that is reachable(), kept apart so a validator can report it as its
// own fault rather than as unreadable bytes.
func parseThreshold(raw []byte) (*parsedThreshold, error) {
	if s, ok := jsonString(raw); ok {
		n, err := canonicalHex(s)
		if err != nil {
			return nil, err
		}
		return &parsedThreshold{count: n}, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("a threshold must be a count or a list of weights")
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("a weighted threshold with no weights can never be met")
	}

	// A list whose every entry is itself a list is several clauses. Anything
	// else is one clause, the way the reference decides it: a list mixing
	// clauses with bare weights does not say which of them must be met, and is
	// refused below when a clause element turns out to be a list.
	clauses := [][]json.RawMessage{items}
	if allLists(items) {
		clauses = clauses[:0]
		for _, item := range items {
			var inner []json.RawMessage
			if err := json.Unmarshal(item, &inner); err != nil {
				return nil, fmt.Errorf("a threshold clause is not a list: %w", err)
			}
			clauses = append(clauses, inner)
		}
	}

	t := &parsedThreshold{weighted: true}
	for _, clause := range clauses {
		if len(clause) == 0 {
			return nil, fmt.Errorf("a threshold clause with no weights can never be met")
		}
		elems := make([]thresholdElement, 0, len(clause))
		for _, item := range clause {
			el, err := parseThresholdElement(item)
			if err != nil {
				return nil, err
			}
			elems = append(elems, el)
		}
		t.clauses = append(t.clauses, elems)
	}
	return t, nil
}

func allLists(items []json.RawMessage) bool {
	for _, item := range items {
		s := strings.TrimSpace(string(item))
		if s == "" || s[0] != '[' {
			return false
		}
	}
	return true
}

// parseThresholdElement reads one clause entry: a weight, or a one-entry map
// from a weight to a list of weights.
func parseThresholdElement(item json.RawMessage) (thresholdElement, error) {
	if s, ok := jsonString(item); ok {
		w, err := parseWeight(s)
		if err != nil {
			return thresholdElement{}, err
		}
		return thresholdElement{weight: w}, nil
	}
	trimmed := strings.TrimSpace(string(item))
	if trimmed == "" || trimmed[0] != '{' {
		return thresholdElement{}, fmt.Errorf("a threshold clause holds %s, which is neither "+
			"a weight nor a weighted set of weights", trimmed)
	}
	// Decoded by hand rather than into a Go map so that a key given twice is
	// seen and refused rather than silently collapsed to one.
	fields, err := scanFields([]byte(trimmed))
	if err != nil {
		return thresholdElement{}, fmt.Errorf("a weighted set in a threshold is not readable: %w", err)
	}
	if len(fields) != 1 {
		return thresholdElement{}, fmt.Errorf("a weighted set in a threshold maps exactly one "+
			"weight to its list of weights, and this one has %d entries", len(fields))
	}
	w, err := parseWeight(fields[0].Name)
	if err != nil {
		return thresholdElement{}, err
	}
	var inner []string
	if err := json.Unmarshal(fields[0].Value, &inner); err != nil {
		return thresholdElement{}, fmt.Errorf("the weighted set %q is not a list of weights: %w",
			fields[0].Name, err)
	}
	if len(inner) == 0 {
		return thresholdElement{}, fmt.Errorf("the weighted set %q weighs no keys, so it can "+
			"never be met", fields[0].Name)
	}
	set := make([]*big.Rat, 0, len(inner))
	for _, s := range inner {
		r, err := parseWeight(s)
		if err != nil {
			return thresholdElement{}, err
		}
		set = append(set, r)
	}
	return thresholdElement{weight: w, set: set}, nil
}

// parseWeight reads one weight as an exact rational between 0 and 1.
//
// Only whole numbers and n/d ratios are accepted. A decimal like "0.5" is
// refused rather than rounded, matching the reference, because two spellings of
// the same weight would otherwise digest differently.
func parseWeight(s string) (*big.Rat, error) {
	num, den := s, "1"
	if i := strings.IndexByte(s, '/'); i >= 0 {
		num, den = s[:i], s[i+1:]
	}
	n, err1 := strconv.ParseUint(num, 10, 64)
	d, err2 := strconv.ParseUint(den, 10, 64)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%q is not a weight; weights are written as a whole number "+
			"or a fraction such as \"1/2\"", s)
	}
	if d == 0 {
		return nil, fmt.Errorf("the weight %q has a denominator of zero", s)
	}
	r := new(big.Rat).SetFrac(new(big.Int).SetUint64(n), new(big.Int).SetUint64(d))
	if r.Cmp(ratOne) > 0 {
		return nil, fmt.Errorf("the weight %q is not between 0 and 1", s)
	}
	return r, nil
}

// slots is how many keys a weighted threshold weighs, one per bare weight and
// one per entry of each weighted set.
func (t *parsedThreshold) slots() int {
	n := 0
	for _, c := range t.clauses {
		for _, e := range c {
			n += e.keys()
		}
	}
	return n
}

// reachable reports, in plain words, why a weighted threshold could never be
// met even if every key signed: a clause, or a weighted set, whose weights sum
// to less than one. The reference refuses such a threshold outright.
func (t *parsedThreshold) reachable() error {
	if t == nil || !t.weighted {
		return nil
	}
	for i, c := range t.clauses {
		top := new(big.Rat)
		for _, e := range c {
			if e.set != nil {
				if sum := sumRats(e.set); sum.Cmp(ratOne) < 0 {
					return fmt.Errorf("the weighted set %s in clause %d sums to %s, which never "+
						"reaches 1", ratString(e.weight), i, sum.RatString())
				}
			}
			top.Add(top, e.weight)
		}
		if top.Cmp(ratOne) < 0 {
			return fmt.Errorf("the weights in clause %d sum to %s, which never reaches 1, so "+
				"no set of signatures could ever satisfy it", i, top.RatString())
		}
	}
	return nil
}

func sumRats(rs []*big.Rat) *big.Rat {
	sum := new(big.Rat)
	for _, r := range rs {
		sum.Add(sum, r)
	}
	return sum
}

// exceeds reports whether this threshold can never be met by n keys, and says
// why in plain words.
func (t *parsedThreshold) exceeds(n int) (bool, string) {
	if t == nil {
		return false, ""
	}
	if !t.weighted {
		if t.count == 0 {
			return true, "the threshold is zero, so no signature would ever be required"
		}
		if t.count > uint64(n) {
			return true, fmt.Sprintf("the threshold is %d but only %d keys are supplied", t.count, n)
		}
		return false, ""
	}
	if got := t.slots(); got != n {
		return true, fmt.Sprintf("the threshold gives %d weights for %d keys", got, n)
	}
	if err := t.reachable(); err != nil {
		return true, err.Error()
	}
	return false, ""
}

// satisfiedBy reports whether signatures by the keys at these positions meet
// this threshold, exactly as keripy 1.3.6's Tholder.satisfy decides it.
//
// Each position counts once however many signatures name it. A count is met by
// that many distinct positions. A weighted threshold is met when every clause
// is; a position beyond the keys it weighs meets nothing, and makes the whole
// answer no, as it does in the reference.
func (t *parsedThreshold) satisfiedBy(at map[int]bool) bool {
	if t == nil || len(at) == 0 {
		return false
	}
	if !t.weighted {
		return t.count > 0 && uint64(len(at)) >= t.count
	}
	size := t.slots()
	for p := range at {
		if p < 0 || p >= size {
			return false
		}
	}
	offset := 0
	for _, c := range t.clauses {
		clause := new(big.Rat)
		for _, e := range c {
			if e.set == nil {
				if at[offset] {
					clause.Add(clause, e.weight)
				}
				offset++
				continue
			}
			inner := new(big.Rat)
			for _, w := range e.set {
				if at[offset] {
					inner.Add(inner, w)
				}
				offset++
			}
			if inner.Cmp(ratOne) >= 0 {
				clause.Add(clause, e.weight)
			}
		}
		if clause.Cmp(ratOne) < 0 {
			return false
		}
	}
	return true
}

// SatisfiesThreshold reports whether signatures by the keys at the given
// positions meet a signing threshold, given exactly as it appears in an event's
// kt or nt field ("2", ["1/2","1/2"], [["1","1"],["1","1"]], or a clause of
// weighted sets such as [{"1/2":["1","1"]},{"1/2":["1","1"]}]).
//
// A position is a place in the key list the threshold weighs: the index of a
// verified signature for kt, or the prior-next place it opened for a prior nt.
// Each position counts once. This is the rule every validator in this package
// applies, exported so that code holding the positions some other way asks the
// same question rather than re-deriving it.
//
// An unreadable threshold, or one no set of signatures could ever meet, is an
// error rather than a no, so a caller cannot mistake a broken event for an
// unsigned one.
func SatisfiesThreshold(threshold json.RawMessage, positions []int) (bool, error) {
	t, err := parseThreshold(threshold)
	if err != nil {
		return false, err
	}
	if err := t.reachable(); err != nil {
		return false, err
	}
	at := make(map[int]bool, len(positions))
	for _, p := range positions {
		if p < 0 {
			return false, fmt.Errorf("%d is not a place in a key list", p)
		}
		at[p] = true
	}
	return t.satisfiedBy(at), nil
}

// render writes the threshold the way the reference serialises it: a count as
// a hex string, weights reduced to lowest terms with whole numbers written bare,
// and a single clause written flat rather than as a list holding one list.
func (t *parsedThreshold) render() json.RawMessage {
	if !t.weighted {
		v, _ := json.Marshal(strconv.FormatUint(t.count, 16))
		return v
	}
	var b strings.Builder
	writeClause := func(c []thresholdElement) {
		b.WriteByte('[')
		for i, e := range c {
			if i > 0 {
				b.WriteByte(',')
			}
			if e.set == nil {
				b.WriteString(strconv.Quote(ratString(e.weight)))
				continue
			}
			b.WriteString("{" + strconv.Quote(ratString(e.weight)) + ":[")
			for j, w := range e.set {
				if j > 0 {
					b.WriteByte(',')
				}
				b.WriteString(strconv.Quote(ratString(w)))
			}
			b.WriteString("]}")
		}
		b.WriteByte(']')
	}
	if len(t.clauses) == 1 {
		writeClause(t.clauses[0])
	} else {
		b.WriteByte('[')
		for i, c := range t.clauses {
			if i > 0 {
				b.WriteByte(',')
			}
			writeClause(c)
		}
		b.WriteByte(']')
	}
	return json.RawMessage(b.String())
}

// ratString writes a weight as the reference does: "1/2", or "0" and "1" bare.
func ratString(r *big.Rat) string { return r.RatString() }

// -----------------------------------------------------------------------------
// Building: thresholds as a caller supplies them
// -----------------------------------------------------------------------------

// threshold is a signing threshold as it will appear in the event, plus the
// fewest keys that could satisfy it.
//
// The size is kept because it is the only check available at build time: a
// threshold of 3 over 2 keys can never be met, and an identity that commits to
// one has locked itself out permanently.
type threshold struct {
	value json.RawMessage
	size  int
}

// parseThresholdValue renders a threshold supplied by a caller the way the
// reference writes it.
//
// Three input shapes are accepted because three are produced: absent (take the
// default), a count, and a list of weights. A count string is hexadecimal, and
// a bare JSON number is accepted as an unambiguous count, but both are written
// out as a hex string, never a number. Weights are re-rendered rather than
// passed through, because the incoming bytes may carry whitespace or unreduced
// fractions, and either would change the event's identifier.
func parseThresholdValue(raw json.RawMessage, def int) (threshold, error) {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed == "null" {
		return numericThreshold(def)
	}

	switch trimmed[0] {
	case '[':
		return weightedThreshold(trimmed)
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return threshold{}, err
		}
		// A weighted threshold arriving as a JSON string is how the reference
		// accepts one from a command line or config file. Unwrapped here rather
		// than rejected, so the same vector data reads the same either way.
		if strings.Contains(s, "[") {
			return weightedThreshold(s)
		}
		n, err := strconv.ParseInt(s, 16, 32)
		if err != nil {
			return threshold{}, fmt.Errorf("%q is not a hexadecimal threshold", s)
		}
		return numericThreshold(int(n))
	default:
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return threshold{}, fmt.Errorf("%q is not a threshold", trimmed)
		}
		i, err := strconv.Atoi(n.String())
		if err != nil {
			return threshold{}, fmt.Errorf("threshold %s is not a whole number", n)
		}
		return numericThreshold(i)
	}
}

func numericThreshold(n int) (threshold, error) {
	if n < 0 {
		return threshold{}, fmt.Errorf("threshold %d is negative", n)
	}
	t := parsedThreshold{count: uint64(n)}
	// A count threshold says nothing about how many keys exist, so the fewest
	// keys that can satisfy it is the count itself.
	return threshold{value: t.render(), size: n}, nil
}

// weightedThreshold reads weights through the one threshold reader, refuses a
// threshold that could never be met, and renders it as the reference does.
func weightedThreshold(js string) (threshold, error) {
	t, err := parseThreshold([]byte(js))
	if err != nil {
		return threshold{}, fmt.Errorf("%s is not a list of weights: %w", js, err)
	}
	if !t.weighted {
		return threshold{}, fmt.Errorf("%s is not a list of weights", js)
	}
	if err := t.reachable(); err != nil {
		return threshold{}, err
	}
	// A weight sits against a specific key by position, so a weighted threshold
	// states exactly how many keys there must be.
	return threshold{value: t.render(), size: t.slots()}, nil
}

// ample returns the witness threshold to use when a rotation does not state
// one.
//
// It is the smallest threshold that still tolerates the most faults a set of
// this size can survive — the reference's derivation, reproduced rather than
// approximated. A simple majority looks close enough and is not: it accepts
// histories the rest of the network will reject, and only once real witnesses
// disagree.
func ample(n int) int {
	if n < 1 {
		return 0
	}
	// The most and the least faults tolerable subject to n >= 3f+1; the
	// resulting thresholds are compared and the weaker one taken.
	least := max(1, (n-1)/3)
	most := max(1, ceilDiv(n-1, 3))
	return min(n, ceilDiv(n+least+1, 2), ceilDiv(n+most+1, 2))
}

// ceilDiv divides and rounds up, for non-negative inputs.
func ceilDiv(a, b int) int {
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}
