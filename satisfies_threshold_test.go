package keri

import (
	"encoding/json"
	"testing"
)

// SatisfiesThreshold is the one answer to "do signatures at these places meet
// this threshold". Every expectation here is keripy 1.3.6's Tholder.satisfy
// for the same threshold and places.
func TestSatisfiesThresholdAgreesWithTheReference(t *testing.T) {
	const (
		twoOwnersStageOne   = `[["1","1"],["1","1"]]`
		twoOwnersStageTwo   = `[["1/2","1/2"],["1/2","1/2"]]`
		threeOwnersStageOne = `[{"1/2":["1","1"]},{"1/2":["1","1"]},{"1/2":["1","1"]}]`
		threeOwnersStageTwo = `[{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]}]`
	)
	for _, tc := range []struct {
		threshold string
		positions []int
		want      bool
	}{
		{`"1"`, []int{0}, true},
		{`"2"`, []int{0}, false},
		{`"2"`, []int{1, 1}, false}, // one place, counted once
		{`"2"`, []int{0, 3}, true},
		{`"0"`, []int{0}, false},
		{`["1/2","1/2","1/2"]`, []int{0, 2}, true},
		{`["1/2","1/2","1/2"]`, []int{1}, false},

		{twoOwnersStageOne, []int{0, 2}, true},
		{twoOwnersStageOne, []int{1, 3}, true},
		{twoOwnersStageOne, []int{0, 1}, false},
		{twoOwnersStageOne, []int{0}, false},

		{twoOwnersStageTwo, []int{0, 1, 2, 3}, true},
		{twoOwnersStageTwo, []int{0, 2}, false},
		{twoOwnersStageTwo, []int{0, 1, 2}, false},

		// Owner 0's two keys alone do not meet it; owner 0's classical key
		// with owner 2's post-quantum key does.
		{threeOwnersStageOne, []int{0, 1}, false},
		{threeOwnersStageOne, []int{0, 5}, true},
		{threeOwnersStageOne, []int{0}, false},
		{threeOwnersStageOne, []int{2, 3}, false},
		{threeOwnersStageOne, []int{0, 2, 4}, true},
		{threeOwnersStageOne, []int{1, 3}, true},
		// A place beyond the keys the threshold weighs makes the answer no.
		{threeOwnersStageOne, []int{0, 6}, false},

		{threeOwnersStageTwo, []int{0, 1, 2, 3}, true},
		{threeOwnersStageTwo, []int{0, 1, 2}, false},
		{threeOwnersStageTwo, []int{0, 1, 4, 5}, true},
		{threeOwnersStageTwo, []int{0, 2, 4}, false},
	} {
		got, err := SatisfiesThreshold(json.RawMessage(tc.threshold), tc.positions)
		if err != nil {
			t.Errorf("%s at %v: %v", tc.threshold, tc.positions, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s at %v: got %v, keripy says %v", tc.threshold, tc.positions, got, tc.want)
		}
	}
}

// A threshold that cannot be read, or that no signatures could ever meet, is
// an error rather than a quiet no.
func TestSatisfiesThresholdRefusesABrokenThreshold(t *testing.T) {
	for _, bad := range []string{`"02"`, `["1/2"]`, `[{"1/2":["1/2"]},"1/2"]`, `2`, `[]`} {
		if _, err := SatisfiesThreshold(json.RawMessage(bad), []int{0}); err == nil {
			t.Errorf("%s was answered rather than refused", bad)
		}
	}
	if _, err := SatisfiesThreshold(json.RawMessage(`"1"`), []int{-1}); err == nil {
		t.Error("a negative place was answered rather than refused")
	}
}
