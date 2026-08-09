package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// A witnessed identity that states no witness threshold takes the reference's
// derived default, not zero.
//
// This diverged for a while: inception could not tell "absent" from "zero"
// because its field was an int, so it refused any witnessed inception that did
// not state one — while the reference filled it in. Rotation and delegation used
// a pointer and behaved correctly, so the same inputs produced different results
// depending on which event kind you asked for.
//
// Defaulting to zero would have been worse than refusing: zero means no witness
// need agree on anything, which is a valid-looking identity with the protection
// switched off.
func TestAWitnessedInceptionWithNoStatedThresholdTakesTheDefault(t *testing.T) {
	wits := []string{
		"BCZ_aHuuxFy3CW3VfIAIAiNmmpVd-1keLj6T6pYD9da6",
		"BL0R47LBuViY8KuXNgAPMjn2O1U95HhtFzrXUS89feT_",
		"BKDtywULdbP7aLdch9RBSjENGeBDD9pqdI6d88ObtAZ_",
	}
	raw, err := BuildInception(InceptionInput{
		Keys:        []string{"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"},
		NextDigests: []string{"EEXekUYwlDVIRTPSGEBJnZBl2Zx6vJfPTQ6XvJpTNhkI"},
		Witnesses:   wits,
		// Toad deliberately absent.
	})
	if err != nil {
		t.Fatalf("a witnessed inception with no stated threshold was refused: %v", err)
	}
	var ev struct {
		BT string `json:"bt"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	// keripy derives 3 for three witnesses. Checked against it directly.
	if ev.BT != "3" {
		t.Fatalf("witness threshold defaulted to %q, want %q — the reference derives it "+
			"from the witness count", ev.BT, "3")
	}
	if strings.Contains(string(raw), `"bt":"0"`) {
		t.Fatal("witness threshold defaulted to zero, meaning no witness need agree")
	}
}

// Zero, stated explicitly, is still honoured — it is a different instruction
// from saying nothing.
func TestAnExplicitZeroWitnessThresholdIsKept(t *testing.T) {
	zero := 0
	raw, err := BuildInception(InceptionInput{
		Keys:        []string{"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"},
		NextDigests: []string{"EEXekUYwlDVIRTPSGEBJnZBl2Zx6vJfPTQ6XvJpTNhkI"},
		Toad:        &zero,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"bt":"0"`) {
		t.Fatalf("an explicit zero was not kept:\n%s", string(raw))
	}
}

// The witness threshold a dip states when none is given is reused from the
// rotation code, so it is worth pinning that it still agrees with the reference.
// keripy's ample(1..19); a majority rule looks close enough and is not.
func TestWitnessThresholdDefaultMatchesTheReference(t *testing.T) {
	want := []int{1, 2, 3, 3, 4, 4, 5, 6, 6, 7, 8, 8, 9, 10, 10, 11, 12, 12, 13}
	for i, w := range want {
		if got := ample(i + 1); got != w {
			t.Errorf("with %d witnesses the derived threshold is %d, but keripy's "+
				"ample() gives %d", i+1, got, w)
		}
	}
}
