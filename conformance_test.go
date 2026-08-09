package keri

import (
	"encoding/base64"
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
			// Cases that assert a verdict or a table rather than bytes are
			// answered by their own assertions instead of by Answer. They are
			// counted as answered: a case that is checked here is not "still
			// to implement", and reporting it as such would understate the work.
			switch c.Kind {
			case "reject":
				assertRefused(t, c)
				done++
				return
			case "property":
				assertProperty(t, c)
				done++
				return
			case "constants":
				assertConstants(t, c)
				done++
				return
			}
			got, err := Answer(c)
			switch {
			case err == ErrNotImplemented:
				todo++
				t.Skipf("not implemented yet — %s", c.Why)
			case err == errAnsweredByAssert:
				// No bytes to compare: the case is a state table or a context
				// fixture, checked by a dedicated assertion.
				switch {
				case c.Kind == "credential":
					assertRevocationState(t, c)
				case c.Kind == "receipt":
					assertReceiptContext(t, c)
				default:
					t.Fatalf("case claims to be answered by assertion, but no "+
						"assertion is registered for kind %q", c.Kind)
				}
				done++
				return
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

// assertConstants checks the CESR code tables the vectors pin.
//
// Codes are normative: an implementation that emits a different prefix produces
// values nothing else can read. The table is asserted against the constants
// this package publishes, so a drift in either place fails here.
func assertConstants(t *testing.T, c Case) {
	t.Helper()
	var want map[string]interface{}
	if err := json.Unmarshal(c.ExpectRaw, &want); err != nil {
		t.Fatalf("the constants table is not readable: %v", err)
	}
	// Matter codes (may be absent on the stream/counter-codes case).
	check := func(key, got string) {
		t.Helper()
		v, ok := want[key]
		if !ok {
			return
		}
		s, ok := v.(string)
		if !ok {
			t.Errorf("constant %q is not a string", key)
			return
		}
		if got != s {
			t.Errorf("constant %q: this package has %q, the vector has %q", key, got, s)
		}
	}
	check("blake3_256", CodeBlake3_256)
	check("ed25519_pubkey", CodeEd25519)
	check("ed25519_pubkey_nontransferable", CodeEd25519N)
	check("ed25519_seed", CodeEd25519Seed)
	check("ed25519_sig", CodeEd25519Sig)
	check("controller_idx_sigs", CounterControllerIdxSigs)
	check("witness_idx_sigs", CounterWitnessIdxSigs)
	check("nontrans_receipt_couples", CounterNonTransReceiptCouples)
	check("trans_receipt_quadruples", CounterTransReceiptQuadruples)
	check("attached_material_quadlets", CounterAttachedMaterialQuadlets)
	// stream/counter-codes uses the long names.
	check("ControllerIdxSigs", CounterControllerIdxSigs)
	check("WitnessIdxSigs", CounterWitnessIdxSigs)
	check("NonTransReceiptCouples", CounterNonTransReceiptCouples)
	check("TransReceiptQuadruples", CounterTransReceiptQuadruples)
	check("AttachedMaterialQuadlets", CounterAttachedMaterialQuadlets)
	if p, ok := want["example_attachment_prefix"].(string); ok && p != "" {
		// A single controller signature group is -A with count 1 → -AAB.
		frame, err := counterFrame(CounterControllerIdxSigs, 1)
		if err != nil {
			t.Fatalf("could not frame a one-signature counter: %v", err)
		}
		if frame != p {
			t.Errorf("example attachment prefix: this package frames %q, the vector has %q",
				frame, p)
		}
	}
}

// assertReceiptContext checks the fixture a receipt is verified against: the
// event bytes, their digest, the controller key and its indexed signature.
func assertReceiptContext(t *testing.T, c Case) {
	t.Helper()
	var in struct {
		EventRawB64 string   `json:"event_raw_b64"`
		Witnesses   []string `json:"witnesses"`
		Toad        int      `json:"toad"`
	}
	if err := json.Unmarshal(c.Input, &in); err != nil {
		t.Fatalf("case input is not a receipt context: %v", err)
	}
	var want struct {
		EventRawB64         string   `json:"event_raw_b64"`
		EventSAID           string   `json:"event_said"`
		AID                 string   `json:"aid"`
		ControllerSigerQB64 string   `json:"controller_siger_qb64"`
		ControllerKey       string   `json:"controller_key"`
		Toad                int      `json:"toad"`
		Witnesses           []string `json:"witnesses"`
	}
	if err := json.Unmarshal(c.ExpectRaw, &want); err != nil {
		t.Fatalf("case expect is not a receipt context: %v", err)
	}
	if in.EventRawB64 != want.EventRawB64 {
		t.Fatal("the event the input carries is not the event the expect names")
	}
	event, err := base64.StdEncoding.DecodeString(want.EventRawB64)
	if err != nil {
		t.Fatalf("the event is not readable base64: %v", err)
	}
	if err := ValidateEvent(event); err != nil {
		t.Fatalf("the context event does not validate: %v", err)
	}
	ev, err := ParseEvent(event)
	if err != nil {
		t.Fatalf("the context event is not parseable: %v", err)
	}
	if ev.SAID != want.EventSAID {
		t.Errorf("event said is %s, expect %s", ev.SAID, want.EventSAID)
	}
	if ev.Identifier != want.AID {
		t.Errorf("event aid is %s, expect %s", ev.Identifier, want.AID)
	}
	if len(ev.Keys) == 0 || ev.Keys[0] != want.ControllerKey {
		t.Errorf("controller key is %v, expect %s", ev.Keys, want.ControllerKey)
	}
	// The controller signature must verify over the event under that key.
	stream := append(append([]byte{}, event...), mustAttachSig(t, want.ControllerSigerQB64)...)
	if err := ValidateStream(stream); err != nil {
		t.Fatalf("the controller signature does not verify over the context event: %v", err)
	}
	if want.Toad != in.Toad {
		t.Errorf("toad on expect is %d, on input is %d", want.Toad, in.Toad)
	}
}

func mustAttachSig(t *testing.T, siger string) []byte {
	t.Helper()
	group, err := AttachControllerSigs([]string{siger})
	if err != nil {
		t.Fatalf("could not frame the controller signature: %v", err)
	}
	return group
}

// assertRevocationState checks that a credential is issued, then revoked, in
// that order — the decision offline verification depends on.
func assertRevocationState(t *testing.T, c Case) {
	t.Helper()
	var in struct {
		CredentialSAID string `json:"credential_said"`
		Registry       string `json:"registry"`
		ISSRawB64      string `json:"iss_raw_b64"`
		REVRawB64      string `json:"rev_raw_b64"`
	}
	if err := json.Unmarshal(c.Input, &in); err != nil {
		t.Fatalf("case input is not a revocation state: %v", err)
	}
	var want struct {
		CredentialSAID string `json:"credential_said"`
		Before         struct {
			Ilk  string `json:"ilk"`
			SAID string `json:"said"`
		} `json:"before"`
		After struct {
			Ilk  string `json:"ilk"`
			SAID string `json:"said"`
		} `json:"after"`
	}
	if err := json.Unmarshal(c.ExpectRaw, &want); err != nil {
		t.Fatalf("case expect is not a pair of states: %v", err)
	}
	iss, err := base64.StdEncoding.DecodeString(in.ISSRawB64)
	if err != nil {
		t.Fatalf("issuance is not readable: %v", err)
	}
	rev, err := base64.StdEncoding.DecodeString(in.REVRawB64)
	if err != nil {
		t.Fatalf("revocation is not readable: %v", err)
	}
	issEvent, err := VerifyTELEvent(iss)
	if err != nil {
		t.Fatalf("the issuance does not verify: %v", err)
	}
	revEvent, err := VerifyTELEvent(rev)
	if err != nil {
		t.Fatalf("the revocation does not verify: %v", err)
	}
	if issEvent.Ilk != want.Before.Ilk || issEvent.SAID != want.Before.SAID {
		t.Errorf("before: got %s/%s, want %s/%s",
			issEvent.Ilk, issEvent.SAID, want.Before.Ilk, want.Before.SAID)
	}
	if revEvent.Ilk != want.After.Ilk || revEvent.SAID != want.After.SAID {
		t.Errorf("after: got %s/%s, want %s/%s",
			revEvent.Ilk, revEvent.SAID, want.After.Ilk, want.After.SAID)
	}
	if revEvent.Prior != issEvent.SAID {
		t.Errorf("revocation chains to %s, issuance is %s", revEvent.Prior, issEvent.SAID)
	}
	status, err := CredentialStatus(want.CredentialSAID, [][]byte{iss})
	if err != nil {
		t.Fatalf("state before revocation: %v", err)
	}
	if status != StatusIssued {
		t.Errorf("before revocation: got %q, want %q", status, StatusIssued)
	}
	status, err = CredentialStatus(want.CredentialSAID, [][]byte{iss, rev})
	if err != nil {
		t.Fatalf("state after revocation: %v", err)
	}
	if status != StatusRevoked {
		t.Errorf("after revocation: got %q, want %q", status, StatusRevoked)
	}
}
