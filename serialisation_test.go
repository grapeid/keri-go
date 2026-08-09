package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

// A seal whose CONTENT contains something shaped like a version string.
//
// The patch that fills in an event's declared size used to replace EVERY match
// in the serialised bytes, so a seal or claim carrying such a value was silently
// rewritten — and because the identifier is a digest of those bytes, the event
// came out with an identifier nobody else would compute. No vector contains such
// a value, so this would have shipped and failed on somebody's real data.
func TestAVersionStringInsideContentIsNotRewritten(t *testing.T) {
	seal := json.RawMessage(`{"note":"KERI10JSON0000ff_"}`)
	raw, err := BuildInteraction(InteractionInput{
		Prefix:    "EPrefix000000000000000000000000000000000000x",
		PriorSAID: "EPrior00000000000000000000000000000000000000x",
		SN:        1, Data: []json.RawMessage{seal},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"note":"KERI10JSON0000ff_"`) {
		t.Fatalf("content was rewritten by the version-string patch:\n%s", string(raw))
	}
}
