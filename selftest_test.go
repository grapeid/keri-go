package keri

import "testing"

// The embedded suite must agree with the file-based one. If it does not, the
// thing that runs on a phone is not the thing that was verified on a desktop.
func TestSelfTestMatchesTheTestSuite(t *testing.T) {
	r := SelfTest()
	if r.Total == 0 {
		t.Fatal("the embedded vectors produced no cases")
	}
	t.Logf("%d cases: %d pass, %d asserted elsewhere, %d unimplemented, %d fail",
		r.Total, r.Passed, r.AssertedElsewhere, r.Unimplemented, r.Failed)
	for _, c := range r.Cases {
		if c.Status == "fail" {
			t.Errorf("%s failed: %s\n  why it matters: %s", c.ID, c.Detail, c.Why)
		}
	}
	if !r.OK() {
		t.Error("the embedded suite reports failures the file-based one does not")
	}
}
