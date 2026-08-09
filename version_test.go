package keri

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Reading an event never requires guessing which version it is.
//
// The version is the first field of the event, at a fixed offset, so an
// implementation that supports both dispatches on what it read. Attempting one
// encoding and falling back to the other on failure would be both unnecessary
// and unsafe: a malformed event of one version can resemble a valid event of
// the other, and the fallback would hide the corruption instead of reporting it.
func TestAnEventSaysWhichVersionItIs(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   InceptionInput
		want Version
	}{
		{"built as 1.0", InceptionInput{Version: V1}, V1},
		{"built as 2.0", InceptionInput{Version: V2}, V2},
		{"version unstated", InceptionInput{}, DefaultVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.Keys = []string{"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"}
			tc.in.NextDigests = []string{"EEXekUYwyf4Blv1U_WFML7YliBR9GJXfl3osKtIevKQN"}
			raw, err := BuildInception(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			proto, got, err := DetectVersion(raw)
			if err != nil {
				t.Fatalf("could not read the version back out of the event: %v", err)
			}
			if proto != ProtocolKERI {
				t.Errorf("read protocol %q, want %q", proto, ProtocolKERI)
			}
			if got != tc.want {
				t.Errorf("read version %s, want %s\nevent: %s", got, tc.want, raw)
			}
		})
	}
}

// The declared size must survive the width difference between the encodings.
//
// A 1.0 version string is 17 characters and a 2.0 one is 16. The size is
// declared inside the string whose length it is counting, so a placeholder
// written at the wrong width leaves the event declaring a length it does not
// have — which is exactly what happened the first time 2.0 was built here.
func TestTheDeclaredSizeMatchesTheEvent(t *testing.T) {
	for _, v := range []Version{V1, V2} {
		raw, err := BuildInception(InceptionInput{
			Keys:        []string{"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"},
			NextDigests: []string{"EEXekUYwyf4Blv1U_WFML7YliBR9GJXfl3osKtIevKQN"},
			Witnesses:   []string{"BCZ_aHuuxFy3CW3VfIAIAiNmmpVd-1keLj6T6pYD9da6"},
			Version:     v,
		})
		if err != nil {
			t.Fatalf("CESR %s: %v", v, err)
		}
		var ev struct {
			V string `json:"v"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		_, _, declared, err := ParseVersionString(ev.V)
		if err != nil {
			t.Fatalf("CESR %s: %v", v, err)
		}
		if declared != len(raw) {
			t.Errorf("CESR %s declares %d bytes but the event is %d: %s",
				v, declared, len(raw), raw)
		}
	}
}

// CESR 1.0 is frozen; CESR 2.0 is not.
//
// This is the finding that decides whether identities may be minted at 2.0, so
// it is pinned here rather than left in a document. The two vector files were
// captured from keripy 1.3.6 and keripy 2.0.0-dev6 with identical inputs. If a
// future pair of oracles agrees on 2.0, this test says so by failing, and the
// default can be reconsidered on evidence.
func TestTheTwoOraclesAgreeOnOneVersionOnly(t *testing.T) {
	load := func(name string) map[string]any {
		b, err := os.ReadFile(filepath.Join("vectors", name))
		if err != nil {
			t.Skipf("vector file not present: %v", err)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a := load("keri_vectors_v2_keripy-1.3.6.json")
	b := load("keri_vectors_v2_keripy-2.0.0-dev6.json")

	casesA, _ := a["cases"].([]any)
	casesB, _ := b["cases"].([]any)
	if len(casesA) == 0 || len(casesA) != len(casesB) {
		t.Fatalf("the two vector files do not pair up: %d and %d cases",
			len(casesA), len(casesB))
	}

	raw := func(c any, ver string) string {
		m := c.(map[string]any)["expect"].(map[string]any)[ver].(map[string]any)
		return m["raw_b64"].(string)
	}

	var agree1, agree2 int
	for i := range casesA {
		if raw(casesA[i], "1.0") == raw(casesB[i], "1.0") {
			agree1++
		}
		if raw(casesA[i], "2.0") == raw(casesB[i], "2.0") {
			agree2++
		}
	}
	if agree1 != len(casesA) {
		t.Errorf("CESR 1.0 was believed frozen, but the two oracles agree on only "+
			"%d of %d cases — if this is real, the default version rests on a false "+
			"premise", agree1, len(casesA))
	}
	if agree2 != 0 {
		t.Errorf("CESR 2.0 now agrees on %d of %d cases across the two oracles. If the "+
			"format has settled, revisit DefaultVersion — this test is the trigger for "+
			"that decision, not an assertion that 2.0 must stay broken", agree2, len(casesA))
	}
}

// A self-addressing identifier does not survive a version change; a basic one
// does. This is the whole migration question, so it is asserted from the
// captured vectors rather than described.
func TestWhichIdentifiersSurviveAVersionChange(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("vectors", "keri_vectors_v2_keripy-1.3.6.json"))
	if err != nil {
		t.Skipf("vector file not present: %v", err)
	}
	var file struct {
		Cases []struct {
			ID       string `json:"id"`
			Survives bool   `json:"identifier_survives_version_change"`
			Input    struct {
				Derivation string `json:"derivation"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		switch c.Input.Derivation {
		case "basic":
			if !c.Survives {
				t.Errorf("%s: a basic identifier is the key itself and should survive "+
					"a version change, but did not", c.ID)
			}
		case "self-addressing":
			if c.Survives {
				t.Errorf("%s: a self-addressing identifier is a digest of an event "+
					"containing the version string, so it cannot survive a version "+
					"change — if it did, the digest is not covering what we think", c.ID)
			}
		}
	}
}

func TestSizesRoundTripThroughBothEncodings(t *testing.T) {
	for _, size := range []int{0, 1, 63, 64, 298, 439, 4095, 262143} {
		for _, v := range []Version{V1, V2} {
			vs, err := VersionString(ProtocolKERI, v, size)
			if err != nil {
				t.Fatalf("CESR %s size %d: %v", v, size, err)
			}
			if len(vs) != versionStringLen(v) {
				t.Fatalf("CESR %s size %d: version string is %d characters, want %d (%q)",
					v, size, len(vs), versionStringLen(v), vs)
			}
			proto, got, back, err := ParseVersionString(vs)
			if err != nil {
				t.Fatalf("could not read back %q: %v", vs, err)
			}
			if proto != ProtocolKERI || got != v || back != size {
				t.Errorf("%q read back as %s/%s/%d, want KERI/%s/%d",
					vs, proto, got, back, v, size)
			}
		}
	}
}

// Base64 sizes are what 2.0 writes; the arithmetic is checked against values
// taken from real keripy events rather than computed the same way twice.
func TestCESRSizeDigitsMatchKeripy(t *testing.T) {
	for _, tc := range []struct {
		digits string
		want   int
	}{
		{"AAEq", 298}, // KERICAAJSONAAEq. on a 298-byte event
		{"AAFY", 344},
		{"AAG2", 438},
		{"AAHl", 485},
	} {
		got, err := b64Decode(tc.digits)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%q decodes to %d, but keripy wrote it on a %d-byte event",
				tc.digits, got, tc.want)
		}
		// And the same value must encode back to the same digits, or events
		// this package builds would declare sizes keripy cannot read.
		back, err := b64Encode(tc.want, 4)
		if err != nil {
			t.Fatal(err)
		}
		if back != tc.digits {
			t.Errorf("%d encodes to %q, but keripy writes %q", tc.want, back, tc.digits)
		}
	}
	// Cross-check against the standard encoder, so a bug in this package's
	// alphabet handling cannot agree with itself.
	if got := base64.RawURLEncoding.EncodeToString([]byte{0, 1, 42}); got != "AAEq" {
		t.Errorf("the CESR alphabet has drifted from base64url: got %q", got)
	}
}
