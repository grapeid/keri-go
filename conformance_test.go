package keri

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// The checklist.
//
// Every case here is something keripy actually produced. A case that fails
// because nothing implements it yet is progress not yet made; a case that fails
// with the WRONG bytes is this implementation disagreeing with the ecosystem,
// and the two are reported differently on purpose — otherwise the second hides
// among the first, which is how a subtle divergence survives to production.
//
// The suite is expected to be incomplete while the implementation is written.
// It is not expected to be wrong.

const vectorPath = "vectors/keri_vectors_v1.json"

func loadForTest(t *testing.T) *VectorFile {
	t.Helper()
	vf, err := LoadVectors(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("could not load the vectors: %v", err)
	}
	return vf
}

// The file itself has to be sound before anything is measured against it.
func TestTheVectorsAreUsable(t *testing.T) {
	vf := loadForTest(t)
	if vf.Version == 0 {
		t.Error("the vector file states no version, so nothing can pin to it")
	}
	if vf.Oracle == "" {
		t.Error("the vector file does not say which implementation produced it")
	}
	seen := map[string]bool{}
	for _, c := range vf.Cases {
		if c.ID == "" {
			t.Error("a case has no id, so a failure could not name it")
		}
		if seen[c.ID] {
			t.Errorf("two cases share the id %q, so one of them is unreachable", c.ID)
		}
		seen[c.ID] = true
		if c.Why == "" {
			t.Errorf("%s does not say why it exists; a failure would report a "+
				"difference without saying what it means", c.ID)
		}
		switch c.Kind {
		case "inception", "rotation", "interaction":
			if c.Expect.RawB64 == "" {
				t.Errorf("%s expects no serialisation, so it asserts nothing", c.ID)
			}
		case "reject":
			if !c.Expect.Refused {
				t.Errorf("%s is a rejection case that does not require a refusal", c.ID)
			}
		}
	}
}

// The bytes in the file must be self-consistent: an identifier is a digest of
// the event it names, so a vector where they disagree is a broken vector rather
// than a failing implementation.
func TestTheVectorsAreInternallyConsistent(t *testing.T) {
	vf := loadForTest(t)
	for _, c := range vf.Cases {
		if c.Expect.RawB64 == "" {
			continue
		}
		raw, err := c.Expect.Raw()
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		// CESR streams are an event JSON blob followed by attachment counters
		// (e.g. `-AAB…`). The whole stream is not one JSON value; check the
		// leading event only.
		event := raw
		if i := indexEventEnd(raw); i >= 0 && i+1 < len(raw) && raw[i+1] == '-' {
			event = raw[:i+1]
		}
		var ev map[string]interface{}
		if err := json.Unmarshal(event, &ev); err != nil {
			t.Errorf("%s: the expected bytes are not a readable event: %v", c.ID, err)
			continue
		}
		// Schema documents use $id as their SAID, not d, and are not KERI events.
		if id, ok := ev["$id"].(string); ok && c.Expect.SAID != "" {
			if id != c.Expect.SAID {
				t.Errorf("%s: the schema's own identifier is %q but the case expects %q",
					c.ID, id, c.Expect.SAID)
			}
			continue
		}
		if c.Expect.SAID != "" {
			if d, _ := ev["d"].(string); d != c.Expect.SAID {
				t.Errorf("%s: the event's own identifier is %q but the case expects %q",
					c.ID, d, c.Expect.SAID)
			}
		}
		// A KERI/ACDC event is ordered: the version string comes first and states
		// the length of what follows. This is the property our stored events did
		// not have, and it went unnoticed for months.
		if len(event) > 6 && string(event[:6]) != `{"v":"` {
			t.Errorf("%s: the expected bytes do not begin with the version string, so "+
				"they are not canonical KERI serialisation", c.ID)
		}
	}
}

// indexEventEnd returns the index of the closing brace of the leading JSON
// object, or -1. Streams append CESR counters immediately after that brace.
func indexEventEnd(raw []byte) int {
	depth := 0
	inString := false
	escape := false
	for i, b := range raw {
		if inString {
			if escape {
				escape = false
				continue
			}
			if b == '\\' {
				escape = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// What this implementation can answer today.
//
// Reported rather than asserted while the implementation is written: this test
// is the progress meter, and it fails only on a WRONG answer, never on a
// missing one.
func TestConformance(t *testing.T) {
	vf := loadForTest(t)
	var done, todo int

	for _, c := range vf.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			got, err := Answer(c)
			switch {
			case err == ErrNotImplemented:
				todo++
				t.Skipf("not implemented yet — %s", c.Why)
			case err != nil:
				t.Fatalf("failed to answer: %v\nwhy this case exists: %s", err, c.Why)
			}
			want, werr := c.Expect.Raw()
			if werr != nil {
				t.Fatalf("the case has no usable expectation: %v", werr)
			}
			if string(got) != string(want) {
				t.Fatalf("this implementation disagrees with %s.\n"+
					"why this case exists: %s\n want: %q\n got:  %q",
					vf.Oracle, c.Why, string(want), string(got))
			}
			done++
		})
	}
	t.Logf("conformance: %d answered, %d still to implement, %d cases total",
		done, todo, len(vf.Cases))
}
