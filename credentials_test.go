package keri

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verifying credentials somebody else produced.
//
// TestConformance already proves this implementation WRITES the same bytes as
// the reference. That is only half of it. The requirement is that a credential
// handed to a phone with no network can be checked there, and a verifier which
// only ever sees its own output would pass every test in this package while
// being unable to check anything real. So everything below works from the
// reference implementation's bytes, and nothing below builds what it checks.

// rawVectorFile re-reads the vector file keeping each expectation's own JSON.
//
// The shared Expectation type carries the fields the byte-producing cases need.
// Two credential cases state something else — a schema's readable form, and a
// pair of before/after state markers — and those are read here rather than by
// widening a type other work in this package depends on.
type rawVectorFile struct {
	Cases []struct {
		ID     string          `json:"id"`
		Kind   string          `json:"kind"`
		Why    string          `json:"why"`
		Input  json.RawMessage `json:"input"`
		Expect json.RawMessage `json:"expect"`
	} `json:"cases"`
}

func loadRawVectors(t *testing.T) rawVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("could not read the vectors: %v", err)
	}
	var vf rawVectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("the vector file is not readable: %v", err)
	}
	return vf
}

func vectorCase(t *testing.T, id string) (input, expect json.RawMessage) {
	t.Helper()
	for _, c := range loadRawVectors(t).Cases {
		if c.ID == id {
			return c.Input, c.Expect
		}
	}
	t.Fatalf("the vector file has no case %q", id)
	return nil, nil
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("a vector's bytes are not readable base64: %v", err)
	}
	return raw
}

// Every credential vector must verify from its bytes alone.
//
// These bytes came out of keripy, not out of this package. If they verify here,
// an implementation on a phone can check a credential issued by anyone; if they
// did not, this implementation would only ever be able to read its own.
func TestEveryCredentialVectorVerifiesOffline(t *testing.T) {
	vf := loadForTest(t)
	checked := 0
	for _, c := range vf.Cases {
		if !strings.HasPrefix(c.ID, "acdc/") || c.Kind != "credential" || c.Expect.RawB64 == "" {
			continue
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			raw, err := c.Expect.Raw()
			if err != nil {
				t.Fatalf("the case has no usable bytes: %v", err)
			}
			var said string
			switch {
			case bytes.HasPrefix(raw, []byte(`{"v":"ACDC`)):
				cred, err := VerifyCredential(raw)
				if err != nil {
					t.Fatalf("a credential the reference produced does not verify: %v\n"+
						"why this case exists: %s", err, c.Why)
				}
				said = cred.SAID
				// The attribute block's own identifier is checked inside
				// VerifyCredential; assert it here too so a regression that
				// dropped the nested check would be visible rather than silent.
				if cred.AttributeSAID == "" {
					t.Error("the credential verified without an attribute block identifier")
				}
			case bytes.HasPrefix(raw, []byte(`{"v":"KERI`)):
				ev, err := VerifyTELEvent(raw)
				if err != nil {
					t.Fatalf("a transaction event the reference produced does not verify: %v\n"+
						"why this case exists: %s", err, c.Why)
				}
				said = ev.SAID
			default:
				// A schema: a JSON Schema document, not a KERI event, so it
				// carries no version string and names itself with $id.
				said, err = VerifySchema(raw)
				if err != nil {
					t.Fatalf("a schema the reference produced does not verify: %v\n"+
						"why this case exists: %s", err, c.Why)
				}
			}
			if said != c.Expect.SAID {
				t.Fatalf("recomputed the identifier as %s but the reference says %s",
					said, c.Expect.SAID)
			}
			checked++
		})
	}
	if checked == 0 {
		t.Fatal("no credential vectors were checked, so this test proves nothing")
	}
}

// The credential's own facts must be readable back out of it.
//
// A verifier decides on what the credential SAYS, so reading the wrong field —
// the issuer where the holder was meant, say — is as dangerous as a digest that
// does not match, and rather harder to notice.
func TestVerifiedCredentialReportsWhatItHolds(t *testing.T) {
	// The facts a credential case states about itself. Read from the raw
	// expectation rather than from the shared Expectation type, which carries
	// only what the byte-producing cases need and is not this work's to widen.
	type credentialExpect struct {
		RawB64      string `json:"raw_b64"`
		Issuer      string `json:"issuer"`
		SchemaSAID  string `json:"schema_said"`
		Registry    string `json:"registry"`
		SubjectSAID string `json:"subject_said"`
		Salt        string `json:"salt"`
	}

	checked := 0
	for _, c := range loadRawVectors(t).Cases {
		if !strings.HasPrefix(c.ID, "acdc/") || c.Kind != "credential" {
			continue
		}
		var want credentialExpect
		if err := json.Unmarshal(c.Expect, &want); err != nil || want.RawB64 == "" {
			continue
		}
		raw := decodeB64(t, want.RawB64)
		if !bytes.HasPrefix(raw, []byte(`{"v":"ACDC`)) {
			continue
		}
		c, want := c, want
		t.Run(c.ID, func(t *testing.T) {
			cred, err := VerifyCredential(raw)
			if err != nil {
				t.Fatalf("the credential does not verify: %v", err)
			}
			if cred.Issuer != want.Issuer {
				t.Errorf("issuer read as %q, the case says %q", cred.Issuer, want.Issuer)
			}
			if cred.SchemaSAID != want.SchemaSAID {
				t.Errorf("schema read as %q, the case says %q", cred.SchemaSAID, want.SchemaSAID)
			}
			if cred.Registry != want.Registry {
				t.Errorf("registry read as %q, the case says %q", cred.Registry, want.Registry)
			}
			if cred.AttributeSAID != want.SubjectSAID {
				t.Errorf("attribute identifier read as %q, the case says %q",
					cred.AttributeSAID, want.SubjectSAID)
			}
			if want.Salt != "" {
				if !cred.Private() {
					t.Error("a credential with a salt was not reported as privacy-preserving")
				}
				if cred.Salt != want.Salt {
					t.Errorf("salt read as %q, the case says %q", cred.Salt, want.Salt)
				}
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no credentials were read back, so this test proves nothing")
	}
}

// acdc/revocation-state/before-and-after.
//
// This case states no bytes to produce — its expectation is the pair of states
// a credential passes through — so it is asserted here rather than by the
// conformance suite, the way the property and rejection cases are.
func TestCredentialTELState(t *testing.T) {
	input, expect := vectorCase(t, "acdc/revocation-state/before-and-after")

	var in struct {
		CredentialSAID string `json:"credential_said"`
		Registry       string `json:"registry"`
		ISSRawB64      string `json:"iss_raw_b64"`
		REVRawB64      string `json:"rev_raw_b64"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		t.Fatalf("case input is not a revocation state: %v", err)
	}
	var want struct {
		CredentialSAID string `json:"credential_said"`
		Before         struct {
			Ilk    string `json:"ilk"`
			SAID   string `json:"said"`
			RawB64 string `json:"raw_b64"`
		} `json:"before"`
		After struct {
			Ilk    string `json:"ilk"`
			SAID   string `json:"said"`
			RawB64 string `json:"raw_b64"`
		} `json:"after"`
	}
	if err := json.Unmarshal(expect, &want); err != nil {
		t.Fatalf("the case's expectation is not a pair of states: %v", err)
	}

	iss := decodeB64(t, in.ISSRawB64)
	rev := decodeB64(t, in.REVRawB64)

	// Each event has to stand on its own before the pair of them means anything.
	issEvent, err := VerifyTELEvent(iss)
	if err != nil {
		t.Fatalf("the issuance does not verify: %v", err)
	}
	revEvent, err := VerifyTELEvent(rev)
	if err != nil {
		t.Fatalf("the revocation does not verify: %v", err)
	}
	if issEvent.Ilk != want.Before.Ilk || issEvent.SAID != want.Before.SAID {
		t.Errorf("the earlier event reads as %s/%s, the case says %s/%s",
			issEvent.Ilk, issEvent.SAID, want.Before.Ilk, want.Before.SAID)
	}
	if revEvent.Ilk != want.After.Ilk || revEvent.SAID != want.After.SAID {
		t.Errorf("the later event reads as %s/%s, the case says %s/%s",
			revEvent.Ilk, revEvent.SAID, want.After.Ilk, want.After.SAID)
	}
	if revEvent.Prior != issEvent.SAID {
		t.Errorf("the revocation chains to %s, but the issuance is %s — they are not one log",
			revEvent.Prior, issEvent.SAID)
	}
	if issEvent.Registry != in.Registry || revEvent.Registry != in.Registry {
		t.Error("an event names a registry other than the credential's own")
	}

	// Before: the credential is issued.
	status, err := CredentialStatus(want.CredentialSAID, [][]byte{iss})
	if err != nil {
		t.Fatalf("the state before revocation could not be decided: %v", err)
	}
	if status != StatusIssued {
		t.Errorf("before revocation the credential reads as %q, expected %q", status, StatusIssued)
	}

	// After: it is revoked. This is the decision the whole case exists for —
	// an implementation that treated "I hold the credential" as valid would
	// return the same answer for both, and would accept a revoked credential.
	status, err = CredentialStatus(want.CredentialSAID, [][]byte{iss, rev})
	if err != nil {
		t.Fatalf("the state after revocation could not be decided: %v", err)
	}
	if status != StatusRevoked {
		t.Errorf("after revocation the credential reads as %q, expected %q", status, StatusRevoked)
	}
}

// A log that does not hang together must not produce an answer.
//
// The realistic attack is a holder who presents a credential and withholds its
// revocation. Nothing offline can see an event it was never given, so what a
// verifier can do is refuse anything whose chain is broken, out of order, or
// about some other credential — and never quietly answer "issued" for it.
func TestBrokenTELIsRefused(t *testing.T) {
	input, _ := vectorCase(t, "acdc/revocation-state/before-and-after")
	var in struct {
		CredentialSAID string `json:"credential_said"`
		ISSRawB64      string `json:"iss_raw_b64"`
		REVRawB64      string `json:"rev_raw_b64"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		t.Fatalf("case input is not a revocation state: %v", err)
	}
	iss := decodeB64(t, in.ISSRawB64)
	rev := decodeB64(t, in.REVRawB64)

	for _, tc := range []struct {
		name   string
		events [][]byte
		said   string
	}{
		{"the revocation presented as if it opened the log", [][]byte{rev}, in.CredentialSAID},
		{"the events out of order", [][]byte{rev, iss}, in.CredentialSAID},
		{"a log about a different credential", [][]byte{iss, rev},
			"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"no events at all", nil, in.CredentialSAID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if status, err := CredentialStatus(tc.said, tc.events); err == nil {
				t.Fatalf("accepted a log that does not hang together, and called it %q", status)
			}
		})
	}
}

// A credential altered after issuance must not verify.
//
// The point of a self-addressing identifier is that this is impossible to hide:
// change any byte and the digest changes. Worth asserting rather than assuming,
// because an implementation that skipped the nested check would still pass
// every byte-for-byte conformance case.
func TestTamperedCredentialIsRefused(t *testing.T) {
	vf := loadForTest(t)
	var original []byte
	for _, c := range vf.Cases {
		if c.ID == "acdc/issued-into-registry" {
			raw, err := c.Expect.Raw()
			if err != nil {
				t.Fatalf("the case has no usable bytes: %v", err)
			}
			original = raw
		}
	}
	if original == nil {
		t.Fatal("the vector file has no acdc/issued-into-registry case")
	}
	if _, err := VerifyCredential(original); err != nil {
		t.Fatalf("the untampered credential does not verify: %v", err)
	}

	for _, tc := range []struct {
		name string
		from string
		to   string
	}{
		// A claim changed, leaving both digests stale.
		{"a claim edited", `"score":42`, `"score":99`},
		// A claim changed AND the attribute block's own identifier recomputed
		// to match — the forgery that a verifier checking only the outer digest
		// would miss, and the reason the inner one is checked at all.
		{"the attribute block replaced wholesale",
			`"a":{"d":"EEFF9js7kOOsIyAckS0zYVWbHbi2eGmt-0W_ugqVAq3g"`,
			`"a":{"d":"EEFF9js7kOOsIyAckS0zYVWbHbi2eGmt-0W_ugqVAq3h"`},
		// The registry swapped, so the credential would be checked against a
		// revocation log its issuer never wrote.
		{"the registry redirected",
			`"ri":"ENrSFrxOMr5GU_BWUEaJtLtd7l-5eebGO--QX3_o7loo"`,
			`"ri":"ENrSFrxOMr5GU_BWUEaJtLtd7l-5eebGO--QX3_o7lop"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := bytes.Replace(original, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(tampered, original) {
				t.Fatalf("the test did not actually change anything: %q not found", tc.from)
			}
			if _, err := VerifyCredential(tampered); err == nil {
				t.Fatal("a tampered credential verified")
			}
		})
	}
}

// A credential that is not canonically serialised must not verify.
//
// Re-spacing changes no meaning and every digest. A verifier that accepted it
// would compute an identifier nobody else computes, and would then report a
// perfectly good credential as forged — so the honest answer is to say the
// bytes are wrong, not that the credential is.
func TestNonCanonicalCredentialIsRefused(t *testing.T) {
	vf := loadForTest(t)
	for _, c := range vf.Cases {
		if c.ID != "acdc/issued-into-registry" {
			continue
		}
		raw, err := c.Expect.Raw()
		if err != nil {
			t.Fatalf("the case has no usable bytes: %v", err)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, raw, "", "  "); err != nil {
			t.Fatalf("could not re-space the credential: %v", err)
		}
		if _, err := VerifyCredential(pretty.Bytes()); err == nil {
			t.Fatal("a re-spaced credential verified, so its digest was not taken over its bytes")
		}
	}
}

// What this implementation builds must verify under its own verifier.
//
// Separate from conformance on purpose: conformance proves the bytes match the
// reference, this proves the two halves of this package agree with each other.
// Both can be true while either alone is not.
func TestBuiltCredentialsVerify(t *testing.T) {
	vf := loadForTest(t)
	for _, c := range vf.Cases {
		if !strings.HasPrefix(c.ID, "acdc/") || c.Kind != "credential" || c.Expect.RawB64 == "" {
			continue
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			built, err := Answer(c)
			if err != nil {
				t.Fatalf("could not build the case: %v", err)
			}
			switch {
			case bytes.HasPrefix(built, []byte(`{"v":"ACDC`)):
				if _, err := VerifyCredential(built); err != nil {
					t.Fatalf("this implementation built a credential it cannot verify: %v", err)
				}
			case bytes.HasPrefix(built, []byte(`{"v":"KERI`)):
				if _, err := VerifyTELEvent(built); err != nil {
					t.Fatalf("this implementation built an event it cannot verify: %v", err)
				}
			default:
				if _, err := VerifySchema(built); err != nil {
					t.Fatalf("this implementation built a schema it cannot verify: %v", err)
				}
			}
		})
	}
}

// Reading an object must not reorder it.
//
// The failure this guards against does not announce itself: a map would sort
// these alphabetically, the JSON would still be valid, and only the digest
// would differ. It has cost this project twice already.
func TestObjectOrderSurvivesReadingAndWriting(t *testing.T) {
	const original = `{"v":"x","d":"y","a":{"z":1,"a":2},"list":[3,1,2],"n":42}`
	obj, err := parseJSONObject([]byte(original))
	if err != nil {
		t.Fatalf("could not read the object: %v", err)
	}
	again, err := marshalCanonical(obj)
	if err != nil {
		t.Fatalf("could not write the object: %v", err)
	}
	if string(again) != original {
		t.Fatalf("reading and writing changed the bytes:\n want: %s\n got:  %s", original, again)
	}
}

// A field folded in on top of one already there keeps its original position.
//
// This is what puts a credential's own `dt` claim where the format expects it
// rather than at the end of the attribute block. Appending instead would
// produce a different digest, and nothing but a byte comparison would say so.
func TestFoldingAFieldKeepsItsPosition(t *testing.T) {
	obj, err := parseJSONObject([]byte(`{"d":"","i":"who","dt":"then"}`))
	if err != nil {
		t.Fatalf("could not read the object: %v", err)
	}
	if err := obj.setString("dt", "now"); err != nil {
		t.Fatalf("could not set the field: %v", err)
	}
	if err := obj.setString("name", "later"); err != nil {
		t.Fatalf("could not set the field: %v", err)
	}
	raw, err := marshalCanonical(obj)
	if err != nil {
		t.Fatalf("could not write the object: %v", err)
	}
	const want = `{"d":"","i":"who","dt":"now","name":"later"}`
	if string(raw) != want {
		t.Fatalf("folding moved a field:\n want: %s\n got:  %s", want, raw)
	}
}

// Characters Go would escape for HTML must survive a credential unescaped.
//
// Go escapes `<`, `>` and `&` by default so that output is safe to drop into a
// web page. The reference implementation does not, and the digest is over these
// bytes — so an issuer whose name contains an ampersand would otherwise get a
// credential that nothing else in the world can verify. No vector covers this,
// because no vector happens to contain one of those characters; that is exactly
// why it is asserted here.
func TestClaimsAreNotHTMLEscaped(t *testing.T) {
	built, err := BuildCredential(CredentialInput{
		SchemaSAID: "ECK0xZlkjmPoOv0NGGFy2-_j_e9zc0yxayHH0pNeox8w",
		Issuer:     "DGLDzhg7VO1UEFOs4Av-gUU7hcRbdvyO_5nw7IbKBrQt",
		Recipient:  "DGpo2bs7gq8wN3XzpXRDuG9RaY3mxeQ9UkKmfr7aL0g-",
		Data:       json.RawMessage(`{"name":"Smith & Sons <Ltd>","dt":"2024-01-01T00:00:00.000000+00:00"}`),
	})
	if err != nil {
		t.Fatalf("could not build the credential: %v", err)
	}
	if !bytes.Contains(built, []byte("Smith & Sons <Ltd>")) {
		t.Fatalf("the claim was escaped on the way out, so this credential's digest "+
			"differs from the reference's:\n%s", built)
	}
	if _, err := VerifyCredential(built); err != nil {
		t.Fatalf("the credential does not verify: %v", err)
	}
}

// A registry's identifier and its prefix are one digest, so both must be blank
// when it is taken.
//
// Nothing in the serialised event says so, and getting it wrong produces a
// perfectly well-formed registry that no credential can ever name. Asserted
// directly because it is the single least obvious rule in this file.
func TestRegistryIdentifierAndPrefixAreTheSameDigest(t *testing.T) {
	built, err := BuildRegistryInception(RegistryInput{
		Issuer: "DGLDzhg7VO1UEFOs4Av-gUU7hcRbdvyO_5nw7IbKBrQt",
		Nonce:  "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2",
	})
	if err != nil {
		t.Fatalf("could not found the registry: %v", err)
	}
	ev, err := VerifyTELEvent(built)
	if err != nil {
		t.Fatalf("the registry does not verify: %v", err)
	}
	if ev.SAID != ev.Subject {
		t.Fatalf("the registry's identifier is %s but its prefix is %s", ev.SAID, ev.Subject)
	}
}

// A builder must not invent values the caller cannot predict.
//
// A credential whose timestamp or salt was filled in here would be a different
// credential on every call, so the caller could not reproduce it and nobody
// could hold this implementation to a fixed answer. Refusing is the honest
// behaviour; quietly substituting the current time is not.
func TestUnpredictableInputsAreRefused(t *testing.T) {
	base := CredentialInput{
		SchemaSAID: "ECK0xZlkjmPoOv0NGGFy2-_j_e9zc0yxayHH0pNeox8w",
		Issuer:     "DGLDzhg7VO1UEFOs4Av-gUU7hcRbdvyO_5nw7IbKBrQt",
		Data:       json.RawMessage(`{"name":"Alice","dt":"2024-01-01T00:00:00.000000+00:00"}`),
	}

	noTimestamp := base
	noTimestamp.Data = json.RawMessage(`{"name":"Alice"}`)
	if _, err := BuildCredential(noTimestamp); err == nil {
		t.Error("built a credential with no timestamp, so its identifier was invented here")
	}

	noSalt := base
	noSalt.Private = true
	if _, err := BuildCredential(noSalt); err == nil {
		t.Error("built a private credential with no salt, so its identifier was invented here")
	}

	if _, err := BuildRegistryInception(RegistryInput{Issuer: "D" + strings.Repeat("A", 43)}); err == nil {
		t.Error("founded a registry with no nonce, so its identifier was invented here")
	}
}
