package keri

import "testing"

// The exact bytes keripy produces for a source seal couple, captured from it.
func TestSourceSealMatchesKeripy(t *testing.T) {
	const (
		wantSeqner = "0AAAAAAAAAAAAAAAAAAAAAAB"
		said       = "EIl6QsmXv4xyHWtFZl9q3sLVS-16_dAXptWGIZT6FUs4"
		wantAttach = "-GAB0AAAAAAAAAAAAAAAAAAAAAABEIl6QsmXv4xyHWtFZl9q3sLVS-16_dAXptWGIZT6FUs4"
	)
	got, err := SeqnerQB64(1)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantSeqner {
		t.Errorf("sequence number 1 encodes to %q, keripy writes %q", got, wantSeqner)
	}
	attach, err := AttachSourceSeals([]SourceSeal{{SN: 1, SAID: said}})
	if err != nil {
		t.Fatal(err)
	}
	if string(attach) != wantAttach {
		t.Errorf("attachment is\n got %s\nwant %s", attach, wantAttach)
	}
}

func TestSequenceNumbersRoundTrip(t *testing.T) {
	for _, sn := range []uint64{0, 1, 15, 16, 63, 64, 255, 4095, 1 << 32, 1<<64 - 1} {
		q, err := SeqnerQB64(sn)
		if err != nil {
			t.Fatalf("%d: %v", sn, err)
		}
		if len(q) != sizeSeqner {
			t.Errorf("%d encoded to %d characters, expected %d", sn, len(q), sizeSeqner)
		}
		back, err := SeqnerFromQB64(q)
		if err != nil {
			t.Fatalf("%d: %v", sn, err)
		}
		if back != sn {
			t.Errorf("%d round-tripped to %d", sn, back)
		}
	}
}

func TestSourceSealsRoundTrip(t *testing.T) {
	seals := []SourceSeal{
		{SN: 1, SAID: "EIl6QsmXv4xyHWtFZl9q3sLVS-16_dAXptWGIZT6FUs4"},
		{SN: 300, SAID: "EDSmne3OH0ctfNAMIf4osG3Hyb0gO3KE_y51Fu41Qtnd"},
	}
	attach, err := AttachSourceSeals(seals)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSourceSeals(attach)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(seals) {
		t.Fatalf("wrote %d seals, read %d", len(seals), len(back))
	}
	for i := range seals {
		if back[i] != seals[i] {
			t.Errorf("seal %d round-tripped to %+v, expected %+v", i, back[i], seals[i])
		}
	}
}

func TestSourceSealsRefuseNonsense(t *testing.T) {
	if _, err := AttachSourceSeals(nil); err == nil {
		t.Error("an empty source seal group was accepted")
	}
	if _, err := AttachSourceSeals([]SourceSeal{{SN: 1, SAID: "too short"}}); err == nil {
		t.Error("a seal naming a malformed digest was accepted")
	}
	if _, err := ParseSourceSeals([]byte("-CAB")); err == nil {
		t.Error("a different counter code was read as a source seal group")
	}
	if _, err := ParseSourceSeals([]byte("-GAB" + "0AAAAAAAAAAAAAAAAAAAAAAB")); err == nil {
		t.Error("a group claiming one seal but carrying a truncated one was accepted")
	}
	if _, err := AnchoredEvent(nil, SourceSeal{SN: 1, SAID: "x"}); err == nil {
		t.Error("anchoring nothing was accepted")
	}
}
