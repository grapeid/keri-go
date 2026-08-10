package keri

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
)

// Running the conformance suite as ordinary code, not as a Go test.
//
// `go test` does not run on a phone. That matters more than it sounds: the
// arm64 code path is already covered by the desktop suite, but the runtime a
// phone provides is not the runtime a laptop provides — different libc surface
// through cgo, a sandboxed filesystem, tighter memory. An implementation can be
// byte-perfect on a developer machine and wrong on the device it ships to, and
// nothing in a desktop test run would say so.
//
// So the suite is available as a function. It embeds its own vectors, because a
// phone has no working directory to read them from, and returns a structured
// result rather than printing — the caller may be an Objective-C binding with
// nowhere to print to.

//go:embed vectors/keri_vectors_v1.json
var embeddedVectors []byte

// CaseResult is what happened to one conformance case.
type CaseResult struct {
	ID string `json:"id"`
	// Status is "pass", "fail", or "unimplemented".
	Status string `json:"status"`
	// Detail explains a failure. Empty when the case passed.
	Detail string `json:"detail,omitempty"`
	// Why is the case's own explanation of what breaks if an implementation
	// gets it wrong, carried through so a failure on a device says what it
	// means rather than only what differed.
	Why string `json:"why,omitempty"`
}

// SelfTestResult is the outcome of a whole run.
type SelfTestResult struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Unimplemented int `json:"unimplemented"`
	// AssertedElsewhere counts cases that produce no bytes to compare — code
	// tables, state transitions, refusals — and are checked by dedicated
	// assertions in the Go test suite rather than here. They are reported
	// rather than hidden, because a run that quietly skipped a fifth of the
	// suite while reporting "all passed" would be worse than one that failed.
	AssertedElsewhere int          `json:"asserted_elsewhere"`
	Cases             []CaseResult `json:"cases"`
}

// OK reports whether every case that produces bytes produced the right ones.
//
// Unimplemented cases do not fail a run: they are work not yet done, which is a
// different thing from a wrong answer, and conflating them would hide the second
// among the first. Nor do cases checked by assertion elsewhere — but both are
// counted and reported, so a caller can see how much of the suite this run
// actually covered.
func (r *SelfTestResult) OK() bool { return r.Failed == 0 }

// SelfTest runs the embedded conformance vectors and reports the result.
//
// Safe to call anywhere, including from a mobile binding. It reads no files and
// writes none.
func SelfTest() *SelfTestResult {
	out := &SelfTestResult{}

	var vf VectorFile
	if err := json.Unmarshal(embeddedVectors, &vf); err != nil {
		out.Total = 1
		out.Failed = 1
		out.Cases = []CaseResult{{
			ID:     "vectors",
			Status: "fail",
			Detail: fmt.Sprintf("the embedded vectors are not readable: %v", err),
		}}
		return out
	}

	cases := append([]Case(nil), vf.Cases...)
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })

	for _, c := range cases {
		out.Total++
		got, err := Answer(c)
		switch {
		case err == ErrNotImplemented:
			out.Unimplemented++
			out.Cases = append(out.Cases, CaseResult{ID: c.ID, Status: "unimplemented"})
			continue
		case err == errAnsweredByAssert:
			out.AssertedElsewhere++
			out.Cases = append(out.Cases, CaseResult{
				ID: c.ID, Status: "asserted-elsewhere",
			})
			continue
		case err != nil:
			out.Failed++
			out.Cases = append(out.Cases, CaseResult{
				ID: c.ID, Status: "fail", Why: c.Why,
				Detail: fmt.Sprintf("building it failed: %v", err),
			})
			continue
		}

		want, err := c.Expect.Raw()
		if err != nil {
			out.Failed++
			out.Cases = append(out.Cases, CaseResult{
				ID: c.ID, Status: "fail", Why: c.Why,
				Detail: fmt.Sprintf("the expectation is unreadable: %v", err),
			})
			continue
		}
		if string(got) != string(want) {
			out.Failed++
			out.Cases = append(out.Cases, CaseResult{
				ID: c.ID, Status: "fail", Why: c.Why,
				Detail: fmt.Sprintf("produced %s, expected %s",
					base64.StdEncoding.EncodeToString(got),
					base64.StdEncoding.EncodeToString(want)),
			})
			continue
		}
		out.Passed++
		out.Cases = append(out.Cases, CaseResult{ID: c.ID, Status: "pass"})
	}
	return out
}

// SelfTestJSON runs the suite and returns the result as JSON.
//
// The shape a language binding wants: one string across the boundary, rather
// than a structure that gomobile cannot carry.
func SelfTestJSON() (string, error) {
	raw, err := json.Marshal(SelfTest())
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
