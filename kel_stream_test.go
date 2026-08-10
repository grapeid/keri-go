package keri

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Build a log with every attachment shape that changes how a stream is split:
// a plain inception, an interaction, a rotation, and a witnessed event whose
// receipts follow it.
func publishableLog(t *testing.T) ([][]byte, string) {
	t.Helper()
	chain, err := NewKeychain(NewMemoryKeyStore(), "publisher", 1)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := chain.CurrentKeys()
	next, _ := chain.NextDigests()
	icp, err := BuildInception(InceptionInput{Keys: keys, NextDigests: next})
	if err != nil {
		t.Fatal(err)
	}
	signedICP, err := SignEvent(icp, chain.Signers()...)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := ParseEvent(icp)

	ixn, err := BuildInteraction(InteractionInput{
		Prefix: ev.Identifier, PriorSAID: ev.SAID, SN: 1,
		Data: []json.RawMessage{json.RawMessage(`{"note":"anchored"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	signedIXN, err := SignEvent(ixn, chain.Signers()...)
	if err != nil {
		t.Fatal(err)
	}
	ixnEv, _ := ParseEvent(ixn)

	rotKeys, rotNext, err := chain.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	rot, err := BuildRotation(RotationInput{
		Prefix: ev.Identifier, Keys: rotKeys, PriorSAID: ixnEv.SAID,
		SN: 2, NextDigests: rotNext,
	})
	if err != nil {
		t.Fatal(err)
	}
	signedROT, err := SignEvent(rot, chain.Signers()...)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{signedICP.Message, signedIXN.Message, signedROT.Message}, ev.Identifier
}

// The property that matters: what comes out is what went in, byte for byte.
// A stream that round-trips to different bytes has changed something a
// signature covers.
func TestAKeyLogRoundTripsThroughAStream(t *testing.T) {
	log, id := publishableLog(t)
	stream, err := ExportKEL(log)
	if err != nil {
		t.Fatalf("a valid log could not be published: %v", err)
	}
	back, err := ParseKELStream(stream)
	if err != nil {
		t.Fatalf("a stream this package wrote could not be read back: %v", err)
	}
	if len(back) != len(log) {
		t.Fatalf("published %d messages, read back %d", len(log), len(back))
	}
	for i := range log {
		if !bytes.Equal(back[i], log[i]) {
			t.Errorf("message %d changed in the round trip:\n out %s\n in  %s",
				i, back[i], log[i])
		}
	}

	// And the result is usable: a reader that fetched this stream can verify
	// the identity from it, which is the whole purpose.
	res, err := ValidateSignedKEL(back)
	if err != nil {
		t.Fatalf("a log read back from a stream does not validate: %v", err)
	}
	if res.Identifier != id {
		t.Errorf("the stream establishes %s, expected %s", res.Identifier, id)
	}
	if res.Events != len(log) {
		t.Errorf("validated %d events, expected %d", res.Events, len(log))
	}
}

// A stream carrying witness receipts must split correctly too — receipt couples
// are a different width from signatures, and a wrong width reads the next
// message from the wrong offset.
func TestAStreamWithReceiptsSplitsCorrectly(t *testing.T) {
	w1 := mustSigner(t, 'w', false)
	w2 := mustSigner(t, 'x', false)
	ctrl := mustSigner(t, 'c', true)
	wits := []string{mustPub(t, w1), mustPub(t, w2)}

	icp, err := BuildInception(InceptionInput{
		Keys: []string{mustPub(t, ctrl)}, NextDigests: []string{mustDigestOf(t, ctrl)},
		Witnesses: wits, Toad: intPointer(2),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEvent(icp, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := ParseEvent(icp)

	var couples []ReceiptCouple
	for _, w := range []Signer{w1, w2} {
		sig, err := w.Sign(icp)
		if err != nil {
			t.Fatal(err)
		}
		q, err := MatterQB64(CodeEd25519Sig, sig)
		if err != nil {
			t.Fatal(err)
		}
		couples = append(couples, ReceiptCouple{Witness: mustPub(t, w), CigarQB64: q})
	}
	receipt, err := BuildReceiptStream(
		ReceiptInput{Prefix: ev.Identifier, SN: 0, EventSAID: ev.SAID}, couples)
	if err != nil {
		t.Fatal(err)
	}

	// The event followed by its receipt stream, concatenated as they travel.
	stream := append(append([]byte{}, signed.Message...), receipt...)
	back, err := ParseKELStream(stream)
	if err != nil {
		t.Fatalf("a stream carrying receipts could not be split: %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("split into %d messages, expected 2", len(back))
	}
	if !bytes.Equal(back[0], signed.Message) {
		t.Error("the event was not recovered exactly")
	}
	if !bytes.Equal(back[1], receipt) {
		t.Error("the receipt was not recovered exactly")
	}
}

// A source seal is a third width. Getting it wrong would silently misread every
// transaction event a published stream carries.
func TestAStreamWithSourceSealsSplitsCorrectly(t *testing.T) {
	log, _ := publishableLog(t)
	said := "EIl6QsmXv4xyHWtFZl9q3sLVS-16_dAXptWGIZT6FUs4"
	tel, err := BuildRegistryInception(RegistryInput{
		Issuer: "EA0zzubdGY84iWCachkiD1fOWISWIR7xUkBKUsIz2Up2",
		Nonce:  "0ADYvfKAeqRVAyc-Gu0Zc7SN",
	})
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := AnchoredEvent(tel, SourceSeal{SN: 1, SAID: said})
	if err != nil {
		t.Fatal(err)
	}
	stream := append(append([]byte{}, log[0]...), anchored...)
	back, err := ParseKELStream(stream)
	if err != nil {
		t.Fatalf("a stream carrying a source seal could not be split: %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("split into %d messages, expected 2", len(back))
	}
	if !bytes.Equal(back[1], anchored) {
		t.Error("the anchored transaction event was not recovered exactly")
	}
}

// A group this package cannot measure must fail, not be skipped. Skipping means
// resuming at a guessed offset, after which everything is read as something it
// is not.
func TestAnUnmeasurableGroupIsRefusedRatherThanSkipped(t *testing.T) {
	log, _ := publishableLog(t)
	stream, err := ExportKEL(log)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the first counter code with one that does not exist.
	broken := bytes.Replace(stream, []byte("-AAB"), []byte("-ZAB"), 1)
	if bytes.Equal(broken, stream) {
		t.Skip("the log does not contain the expected counter, so this proves nothing")
	}
	if _, err := ParseKELStream(broken); err == nil {
		t.Fatal("a stream with an unrecognised attachment group was split anyway; every " +
			"message after it would be read from a guessed offset")
	}
}

// A published stream is one identity's log.
func TestAStreamMustBeOneIdentity(t *testing.T) {
	a, _ := publishableLog(t)
	b, _ := publishableLog(t)
	if _, err := ExportKEL([][]byte{a[0], b[0]}); err == nil {
		t.Fatal("two identities' events were published as one log; a reader would " +
			"attribute one identity's events to the other")
	}
}

// An unsigned event must not be published.
func TestAnUnsignedEventIsNotPublished(t *testing.T) {
	log, _ := publishableLog(t)
	body, _, err := splitStream(log[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExportKEL([][]byte{body}); err == nil {
		t.Fatal("an event with no attachments was published; nothing attests that its " +
			"controller produced it")
	}
	if _, err := ExportKEL(nil); err == nil {
		t.Error("an empty log was published")
	}
}

func TestReadingRubbishIsRefused(t *testing.T) {
	for _, s := range []string{"", "not a stream", "{\"v\":\"broken\"", "-AAB"} {
		if _, err := ParseKELStream([]byte(s)); err == nil {
			t.Errorf("%q was read as a stream", s)
		}
	}
}

func mustSigner(t *testing.T, tag byte, transferable bool) Signer {
	t.Helper()
	s, err := NewSoftwareSigner(bytes.Repeat([]byte{tag}, 32), transferable)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustPub(t *testing.T, s Signer) string {
	t.Helper()
	p, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustDigestOf(t *testing.T, s Signer) string {
	t.Helper()
	d, err := NextDigest(mustPub(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func intPointer(n int) *int { return &n }
