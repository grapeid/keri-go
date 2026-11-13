package keri

import (
	"bytes"
	"testing"
)

func TestTheEventOfAMessageIsWhatPrecedesItsAttachments(t *testing.T) {
	f := loadSignedKEL(t)
	for i, m := range f["good"] {
		ev, err := EventOfMessage(m)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if !bytes.HasPrefix(m, ev) || len(ev) >= len(m) {
			t.Fatalf("message %d: the event is not the front of the message", i)
		}
		if _, err := ParseEvent(ev); err != nil {
			t.Fatalf("message %d: what came back is not an event: %v", i, err)
		}
	}
	if _, err := EventOfMessage([]byte(`not an event`)); err == nil {
		t.Fatal("bytes with no event were read as one")
	}
}
