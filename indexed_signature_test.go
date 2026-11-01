package keri

import (
	"strings"
	"testing"
)

// The four indexed Ed25519 signature forms, written and read. Each expected
// value is what keripy 1.3.6's Signer(raw=b"c"*32).sign(msg, index=…,
// ondex=…, only=…) produces for the same message, so the code choice and the
// layout of index and prior place are the reference's, not a reading of it.
func TestIndexedSignaturesAreWrittenAsTheReferenceWritesThem(t *testing.T) {
	const tail = "Cd1beCLGbupnu9VDDFo_UCXdgOwgMAdXjj_Ie91M6i0RtBDf29pRAXRgfJrEEuNfkHuqoet4WAdd9I-lVaSS8C"
	s, err := NewSoftwareSigner(seed('c'), true)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Sign([]byte("keri-go dual index vector"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at   SignaturePlace
		want string
	}{
		{SamePlace(5), "AF" + tail},
		{SignaturePlace{Index: 0, Ondex: 1}, "2AAAAB" + tail},
		{SamePlace(70), "2ABGBG" + tail},
		{SignaturePlace{Index: 3, CurrentOnly: true}, "BD" + tail},
		{SignaturePlace{Index: 70, CurrentOnly: true}, "2BBGAA" + tail},
		{SignaturePlace{Index: 1, Ondex: 4095}, "2AAB__" + tail},
	} {
		got, err := EncodeIndexedSignature(raw, tc.at)
		if err != nil {
			t.Errorf("%+v: %v", tc.at, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%+v written as\n %s\nkeripy writes\n %s", tc.at, got, tc.want)
			continue
		}
		back, err := ParseIndexedSignature(got)
		if err != nil {
			t.Errorf("%s could not be read back: %v", got, err)
			continue
		}
		want := tc.at
		if want.CurrentOnly {
			want.Ondex = 0
		}
		if back.At != want || string(back.Raw) != string(raw) {
			t.Errorf("%s read back as %+v, want %+v", got, back.At, want)
		}
	}
	if _, err := EncodeIndexedSignature(raw, SignaturePlace{Index: 0, Ondex: 4096}); err == nil {
		t.Error("a prior place too wide for two digits was written")
	}
}

// A value of the wrong length for its code, an unknown code, and a
// current-only signature carrying a prior place are refused.
func TestMalformedIndexedSignaturesAreRefused(t *testing.T) {
	const tail = "Cd1beCLGbupnu9VDDFo_UCXdgOwgMAdXjj_Ie91M6i0RtBDf29pRAXRgfJrEEuNfkHuqoet4WAdd9I-lVaSS8C"
	for _, bad := range []string{
		"2AAAAB" + tail[:len(tail)-1], // one short
		"2AAAAB" + tail + "A",         // one long
		"2BBGAB" + tail,               // current-only with a prior place
		"2CAAAB" + tail,               // another curve's code
		"CF" + tail,
	} {
		if _, err := ParseIndexedSignature(bad); err == nil {
			t.Errorf("%.6s… (%d characters) was accepted", bad, len(bad))
		}
	}
}

// SignEventAt checks each signer against the key at its index and writes the
// form its places need.
func TestSignEventAtWritesTheFormEachPlaceNeeds(t *testing.T) {
	a, x, c, e := newRotKey(t, 'a'), newRotKey(t, 'x'), newRotKey(t, 'c'), newRotKey(t, 'e')
	icp, icpEv := foundedOn(t, []rotKey{a}, `"1"`, digestsOf(x, c), `"1"`)
	rot := rotationOf(t, icpEv, 1, pubsOf(c), `"1"`, digestsOf(e), `"1"`)

	signed, err := SignEventAt(rot, PlacedSigner{Signer: c.signer,
		At: SignaturePlace{Index: 0, Ondex: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(signed.Attachment), "-AAB2AAAAB") {
		t.Fatalf("attachment begins %.10s, want a 2A signature at index 0, prior place 1",
			signed.Attachment)
	}
	if _, err := ValidateSignedKEL([][]byte{icp, signed.Message}); err != nil {
		t.Fatalf("the signed rotation was refused: %v", err)
	}
	if _, err := SignEventAt(rot, PlacedSigner{Signer: x.signer, At: SamePlace(0)}); err == nil {
		t.Fatal("a signer holding a key the event does not declare at its index was accepted")
	}
	if _, err := SignEventAt(rot, PlacedSigner{Signer: c.signer, At: SamePlace(1)}); err == nil {
		t.Fatal("a signer at an index beyond the event's keys was accepted")
	}
}
