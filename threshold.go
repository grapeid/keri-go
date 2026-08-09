package keri

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Thresholds: how many of an identity's keys must sign, and how many of its
// witnesses must agree.
//
// One implementation, used by every event kind. It existed three times before
// this — inception, rotation and delegation were written in parallel by people
// who correctly refused to reach into each other's files — and three copies of a
// rule this subtle is three chances to disagree with the reference in a way that
// only shows up on somebody else's machine.
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

// parseThresholdValue renders a threshold the way the reference does.
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
		// A bare JSON number. Accepted on the way in — it is an unambiguous
		// count — but written back out as a hex string, which is the only form
		// a peer will read.
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
	// Encoded by hand rather than through json.Marshal of a string: the value
	// is a hex count and this keeps the one place it is rendered next to the
	// one place it is parsed.
	v, err := json.Marshal(strconv.FormatInt(int64(n), 16))
	if err != nil {
		return threshold{}, err
	}
	// A count threshold says nothing about how many keys exist, so the fewest
	// keys that can satisfy it is the count itself.
	return threshold{value: v, size: n}, nil
}

// weightedThreshold renders fractional weights.
//
// A weighted threshold is one or more clauses of weights; the signatures
// satisfy it when every clause's weights sum to at least one. A single clause
// is written flat (["1/2","1/2","1/2"]) rather than nested, which is the form
// the reference emits and therefore the only form that digests the same.
func weightedThreshold(js string) (threshold, error) {
	var nested [][]string
	if err := json.Unmarshal([]byte(js), &nested); err != nil {
		var flat []string
		if err2 := json.Unmarshal([]byte(js), &flat); err2 != nil {
			return threshold{}, fmt.Errorf("%s is not a list of weights: %w", js, err)
		}
		nested = [][]string{flat}
	}
	if len(nested) == 0 {
		return threshold{}, fmt.Errorf("a weighted threshold with no weights "+
			"can never be met: %s", js)
	}

	out := make([][]string, 0, len(nested))
	size := 0
	for _, clause := range nested {
		if len(clause) == 0 {
			return threshold{}, fmt.Errorf("a threshold clause with no weights "+
				"can never be met: %s", js)
		}
		rendered := make([]string, 0, len(clause))
		sumNum, sumDen := 0, 1
		for _, w := range clause {
			num, den, err := weight(w)
			if err != nil {
				return threshold{}, err
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
			return threshold{}, fmt.Errorf("threshold clause %v sums to less than "+
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
		return threshold{}, err
	}
	// A weight sits against a specific key by position, so a weighted threshold
	// states exactly how many keys there must be.
	return threshold{value: v, size: size}, nil
}

// weight parses one weight as an exact rational.
//
// Exact rather than floating point on purpose: weights are compared against 1
// and summed, and a float sum of thirds does not reach 1. Only whole numbers
// and n/d ratios are accepted — a decimal like "0.5" is refused rather than
// rounded, matching the reference, because two spellings of the same weight
// would otherwise digest differently.
func weight(w string) (num, den int, err error) {
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
