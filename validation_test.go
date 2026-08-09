package keri

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Validation is the part of this package that produces a verdict rather than
// bytes, so it is tested the other way round from everything else: the cases
// that matter most are the ones that must be REFUSED, and a refusal is only
// worth anything if it says what was wrong.
//
// Two things are asserted for every refusal case:
//
//  1. it is refused at all; and
//  2. among the faults reported is the one the vector says is wrong.
//
// The second is what stops a validator passing this suite by refusing
// everything. It is asserted as "contains" rather than "equals" on purpose:
// several of these vectors were made by altering a byte of a valid event, and
// altering a byte breaks more than one rule at once. reject/undefined-field, for
// instance, appends a field — which is an undefined field AND a version string
// that now lies AND a digest that no longer matches. All three are true, all
// three are reported, and demanding exactly one of them would be demanding that
// the validator look away from the other two.

// rejectionConcern maps what a vector says is wrong onto the fault kind this
// implementation reports for it. Keyed on the vector's own "because" text so
// the mapping is driven by the case data rather than by its id.
var rejectionConcern = map[string]FaultKind{
	"the contents do not digest to the claimed identifier":                    FaultSAIDMismatch,
	"the rotation key was not committed to by the prior event's next digests": FaultKeyNotPrecommitted,
	"sequence number 2 does not follow the prior event at sn 0":               FaultSequenceSkip,
	"the prior-event digest does not match the SAID of the previous event":    FaultPriorDigestMismatch,
	"the signing threshold is larger than the number of keys supplied":        FaultThresholdExceedsKeys,
	"the event carries a field the schema does not define":                    FaultUndefinedField,
	"the witness cigar does not verify under the witness identifier":          FaultReceiptSignature,
	"the signing identifier is not in the event's witness list":               FaultUndesignatedWitness,
	"the stream ends before the attached material is complete":                FaultStreamTruncated,
}

// rejectInput is the material a refusal case supplies. Which fields are present
// is what says how the case must be checked — the same way a real caller
// decides, from what it was given rather than from a label.
type rejectInput struct {
	RawB64      string   `json:"raw_b64"`
	PriorRawB64 string   `json:"prior_event_raw_b64"`
	EventRawB64 string   `json:"event_raw_b64"`
	Designated  []string `json:"designated_witnesses"`
	Because     string   `json:"because"`
}

// assertRefused runs one refusal case and requires a refusal that names what is
// wrong.
func assertRefused(t *testing.T, c Case) {
	t.Helper()
	var in rejectInput
	if err := json.Unmarshal(c.Input, &in); err != nil {
		t.Fatalf("the case input is not readable: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(in.RawB64)
	if err != nil {
		t.Fatalf("the case's bytes are not readable: %v", err)
	}

	err = validateWhateverWasGiven(t, raw, in)
	if err == nil {
		t.Fatalf("ACCEPTED something that must be refused.\n"+
			"why this case exists: %s\nwhat is wrong with it: %s", c.Why, c.Expect.Because)
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("refused, but not with a fault this suite can read: %v", err)
	}
	if len(ve.Faults) == 0 {
		t.Fatalf("refused without saying why, which tells a reader of a log nothing")
	}
	want, known := rejectionConcern[c.Expect.Because]
	if !known {
		t.Fatalf("this suite has no fault kind for %q, so the refusal cannot be checked "+
			"against what the vector says is wrong", c.Expect.Because)
	}
	if !ve.Has(want) {
		t.Fatalf("refused, but not for the reason the vector gives.\n"+
			"the vector says: %s (expected fault %q)\nthis implementation said: %v",
			c.Expect.Because, want, err)
	}
	for _, f := range ve.Faults {
		if strings.TrimSpace(f.Detail) == "" {
			t.Errorf("fault %q carries no explanation; somebody reading this refusal in a "+
				"log could not tell a bug from an attack", f.Kind)
		}
	}
}

// validateWhateverWasGiven picks the check from the material supplied, not from
// the case id. A case that carries a predecessor is a chaining question; one
// whose bytes are a receipt is a witness question; one with attachments is a
// stream question; anything else stands on its own.
func validateWhateverWasGiven(t *testing.T, raw []byte, in rejectInput) error {
	t.Helper()

	event, attached, splitErr := splitStream(raw)
	if splitErr != nil {
		return ValidateEvent(raw)
	}

	if ev, err := ParseEvent(event); err == nil && ev.Ilk == "rct" {
		covered, derr := base64.StdEncoding.DecodeString(in.EventRawB64)
		if derr != nil {
			t.Fatalf("a receipt case must carry the event it covers: %v", derr)
		}
		return ValidateReceipts(raw, covered, in.Designated)
	}

	if in.PriorRawB64 != "" {
		prior, derr := base64.StdEncoding.DecodeString(in.PriorRawB64)
		if derr != nil {
			t.Fatalf("the case's prior event is not readable: %v", derr)
		}
		return ValidateKEL([][]byte{prior, event})
	}

	if len(attached) > 0 {
		return ValidateStream(raw)
	}
	return ValidateEvent(event)
}

// assertProperty checks the things that must HOLD.
//
// Both derivations are real. An implementation that always sets the identifier
// to the event digest breaks every single-key identity that already exists; one
// that always sets it to the key cannot make a multi-signature identity at all.
// So both are asserted, and the difference between them is asserted too.
func assertProperty(t *testing.T, c Case) {
	t.Helper()
	var in struct {
		RawB64 string `json:"raw_b64"`
	}
	if err := json.Unmarshal(c.Input, &in); err != nil {
		t.Fatalf("the case input is not readable: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(in.RawB64)
	if err != nil {
		t.Fatalf("the case's bytes are not readable: %v", err)
	}
	if err := ValidateEvent(raw); err != nil {
		t.Fatalf("refused an event that must be accepted: %v\nwhy this case exists: %s",
			err, c.Why)
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("could not read the event: %v", err)
	}

	// The identifier is never taken from the d field: re-deriving it is the
	// whole point.
	said, err := ComputeSAID(raw)
	if err != nil {
		t.Fatalf("could not re-derive the event's digest: %v", err)
	}
	if c.Expect.SAID != "" && said != c.Expect.SAID {
		t.Errorf("the event's contents digest to %s and the vector says %s", said, c.Expect.SAID)
	}
	if c.Expect.AID != "" && ev.Identifier != c.Expect.AID {
		t.Errorf("the event names the identity %s and the vector says %s",
			ev.Identifier, c.Expect.AID)
	}

	switch c.Assert {
	case "aid_equals_said":
		if ev.Derivation() != DerivationSelfAddressing {
			t.Errorf("the identifier %s is not self-addressing, so it cannot be the digest "+
				"of its own inception event", ev.Identifier)
		}
		if ev.Identifier != said {
			t.Errorf("a self-addressing identifier IS the digest of the event that created "+
				"it: identifier %s, digest %s", ev.Identifier, said)
		}
	case "aid_equals_key_not_said":
		if ev.Derivation() != DerivationBasic {
			t.Errorf("single-key inception uses basic derivation, but %s is a digest",
				ev.Identifier)
		}
		if len(ev.Keys) != 1 {
			t.Fatalf("basic derivation is single-key, and this event carries %d keys",
				len(ev.Keys))
		}
		if ev.Identifier != ev.Keys[0] {
			t.Errorf("a basic identifier IS its public key: identifier %s, key %s",
				ev.Identifier, ev.Keys[0])
		}
		if ev.Identifier == said {
			t.Errorf("the identifier equals the event digest, which would make this a " +
				"self-addressing identity rather than a single-key one")
		}
	case "":
		// Nothing more than the said/aid agreement above is asserted.
	default:
		t.Fatalf("this suite does not know the property %q", c.Assert)
	}
}

// No valid event in the whole vector file may be refused.
//
// The other half of the job. A validator that refuses everything passes every
// refusal case above and is useless, and worse, it fails CLOSED in a way that
// looks like security. This test is what stops that: every event keripy
// actually produced must be accepted.
func TestValidationRefusesNothingKeripyProduced(t *testing.T) {
	vf := loadForTest(t)
	checked := 0
	for _, c := range vf.Cases {
		switch c.Kind {
		case "inception", "rotation", "interaction", "delegation":
		default:
			continue
		}
		raw, err := c.Expect.Raw()
		if err != nil {
			continue
		}
		if err := ValidateEvent(raw); err != nil {
			t.Errorf("%s: refused an event the reference implementation produced: %v\n"+
				"why this case exists: %s", c.ID, err, c.Why)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no valid events were checked, so this test proves nothing")
	}
	t.Logf("accepted %d events produced by the reference implementation", checked)
}

// Receipt bodies are events too, and their d field is the digest of the event
// they cover rather than of themselves — a rule that is easy to get wrong in the
// direction of refusing every receipt ever sent.
func TestValidationAcceptsReceiptBodies(t *testing.T) {
	vf := loadForTest(t)
	for _, c := range vf.Cases {
		if c.Kind != "receipt" {
			continue
		}
		raw, err := c.Expect.Raw()
		if err != nil {
			continue
		}
		event, _, serr := splitStream(raw)
		if serr != nil {
			continue
		}
		ev, perr := ParseEvent(event)
		if perr != nil || ev.Ilk != "rct" {
			continue
		}
		if err := ValidateEvent(event); err != nil {
			t.Errorf("%s: refused a receipt the reference implementation produced: %v", c.ID, err)
		}
	}
}

// The signed streams keripy produced must verify, signature and all. Without
// this, "the attachment parses" would be the only thing the stream cases prove,
// and a parser that reads the right number of bytes but the wrong ones would
// pass.
func TestValidationAcceptsSignedStreams(t *testing.T) {
	vf := loadForTest(t)
	checked := 0
	for _, c := range vf.Cases {
		if c.Kind != "stream" {
			continue
		}
		raw, err := c.Expect.Raw()
		if err != nil {
			continue
		}
		if err := ValidateStream(raw); err != nil {
			t.Errorf("%s: refused a signed stream the reference implementation produced: %v\n"+
				"why this case exists: %s", c.ID, err, c.Why)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no signed streams were checked, so this test proves nothing")
	}
}

// Witness receipts keripy produced must verify against the event they cover, and
// the toad must be counted the way the vectors say.
func TestValidationAcceptsWitnessReceipts(t *testing.T) {
	vf := loadForTest(t)
	checked := 0
	for _, c := range vf.Cases {
		if c.Kind != "receipt" {
			continue
		}
		var in struct {
			EventRawB64 string   `json:"event_raw_b64"`
			Witnesses   []string `json:"witnesses"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil || in.EventRawB64 == "" {
			continue
		}
		stream, err := c.Expect.Raw()
		if err != nil {
			continue
		}
		if _, attached, serr := splitStream(stream); serr != nil || len(attached) == 0 {
			continue
		}
		event, derr := base64.StdEncoding.DecodeString(in.EventRawB64)
		if derr != nil {
			continue
		}
		if err := ValidateReceipts(stream, event, in.Witnesses); err != nil {
			t.Errorf("%s: refused a witness receipt the reference implementation produced: "+
				"%v\nwhy this case exists: %s", c.ID, err, c.Why)
			continue
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no witness receipts were checked, so this test proves nothing")
	}
}

// A rotation chain must validate as a chain, not merely event by event. The
// vectors carry one that runs to sequence number 3, which is what exercises
// pre-rotation across more than a single step.
func TestValidationAcceptsARotationChain(t *testing.T) {
	vf := loadForTest(t)
	byID := map[string]Case{}
	for _, c := range vf.Cases {
		byID[c.ID] = c
	}
	// The chain's own inception is carried in the first rotation's input, so
	// the history is assembled from the vectors rather than guessed at from
	// another case that happens to be an inception.
	first, ok := byID["rot/chain/sn-1"]
	if !ok {
		t.Skip("the vector file does not carry the rotation chain")
	}
	var in struct {
		InceptionRawB64 string `json:"inception_raw_b64"`
	}
	if err := json.Unmarshal(first.Input, &in); err != nil || in.InceptionRawB64 == "" {
		t.Skip("the rotation chain does not carry the inception it starts from")
	}
	icp, err := base64.StdEncoding.DecodeString(in.InceptionRawB64)
	if err != nil {
		t.Fatalf("the chain's inception is not readable: %v", err)
	}
	log := [][]byte{icp}
	for _, id := range []string{"rot/chain/sn-1", "rot/chain/sn-2", "rot/chain/sn-3"} {
		c, ok := byID[id]
		if !ok {
			t.Skipf("the vector file does not carry %s", id)
		}
		raw, err := c.Expect.Raw()
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		log = append(log, raw)
	}
	if err := ValidateKEL(log); err != nil {
		t.Fatalf("refused a key history the reference implementation produced: %v", err)
	}
}

// Reordering a valid history must be refused. Nothing in the vector file states
// this directly, but it is the property the sequence and prior-digest checks
// exist for, and asserting it here keeps them from being quietly weakened.
func TestValidationRefusesAReorderedHistory(t *testing.T) {
	vf := loadForTest(t)
	byID := map[string]Case{}
	for _, c := range vf.Cases {
		byID[c.ID] = c
	}
	first, ok := byID["rot/chain/sn-1"]
	if !ok {
		t.Skip("the vector file does not carry the rotation chain")
	}
	var in struct {
		InceptionRawB64 string `json:"inception_raw_b64"`
	}
	if err := json.Unmarshal(first.Input, &in); err != nil || in.InceptionRawB64 == "" {
		t.Skip("the rotation chain does not carry the inception it starts from")
	}
	icp, err := base64.StdEncoding.DecodeString(in.InceptionRawB64)
	if err != nil {
		t.Fatalf("the chain's inception is not readable: %v", err)
	}
	log := [][]byte{icp}
	for _, id := range []string{"rot/chain/sn-2", "rot/chain/sn-1"} {
		c, ok := byID[id]
		if !ok {
			t.Skipf("the vector file does not carry %s", id)
		}
		raw, err := c.Expect.Raw()
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		log = append(log, raw)
	}
	err = ValidateKEL(log)
	if err == nil {
		t.Fatal("accepted a history whose events are out of order")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || !ve.Has(FaultSequenceSkip) {
		t.Fatalf("refused, but not as a break in the sequence: %v", err)
	}
}

// Every byte of an event is covered by its identifier — so altering any of them
// must be caught.
//
// The refusal cases in the vector file each alter one specific thing. This walks
// the whole event instead, which is what proves the digest check is live rather
// than a check of the few fields somebody remembered to compare. A validator
// that compared fields one by one would pass every vector above and fail here.
func TestValidationCatchesAnyAlteredByte(t *testing.T) {
	vf := loadForTest(t)
	var subject []byte
	for _, c := range vf.Cases {
		if c.ID == "icp/3-keys/2-of-3" {
			raw, err := c.Expect.Raw()
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			subject = raw
		}
	}
	if subject == nil {
		t.Skip("the vector file does not carry icp/3-keys/2-of-3")
	}
	if err := ValidateEvent(subject); err != nil {
		t.Fatalf("the unaltered event was refused, so this test would prove nothing: %v", err)
	}

	tried := 0
	for i := range subject {
		altered := make([]byte, len(subject))
		copy(altered, subject)
		// Stay inside the printable range so the result is often still a
		// readable event; a mutation that only breaks the JSON parse proves
		// less than one that leaves a well-formed but different event.
		altered[i] = nextPrintable(altered[i])
		if altered[i] == subject[i] {
			continue
		}
		tried++
		if err := ValidateEvent(altered); err == nil {
			t.Errorf("accepted an event with byte %d altered from %q to %q — the identifier "+
				"does not actually cover the whole event", i, subject[i], altered[i])
		}
	}
	t.Logf("refused all %d single-byte alterations of a %d-byte event", tried, len(subject))
}

func nextPrintable(b byte) byte {
	switch {
	case b >= 'a' && b < 'z', b >= 'A' && b < 'Z', b >= '0' && b < '9':
		return b + 1
	case b == 'z':
		return 'a'
	case b == 'Z':
		return 'A'
	case b == '9':
		return '0'
	default:
		return b
	}
}

// Serialising the right fields in the wrong order produces a different event,
// and must be refused as one.
//
// This is the failure that made our stored events unreadable to the reference
// implementation for months: a Go map marshals alphabetically, so an event that
// went through one came back with its fields sorted and its identifier wrong.
// Nothing local noticed, because everything local read it back the same way.
func TestValidationRefusesReorderedFields(t *testing.T) {
	// The same fields and the same bytes as a valid interaction, sorted the way
	// a Go map would emit them. The length is unchanged, so the version string
	// still tells the truth and only a validator that looks at the order, or
	// re-derives the digest, catches this.
	reordered := []byte(`{"a":[],"d":"EJMd6X68OTOhdRl5OU4FjSH1CSjjPmQA5R9-C6zkI2E_",` +
		`"i":"DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd",` +
		`"p":"EGRUPYLE0cRa1Q3K0_4-vnnMv_6xRiGIPRSmosO5TB_M","s":"1","t":"ixn",` +
		`"v":"KERI10JSON0000cb_"}`)
	err := ValidateEvent(reordered)
	if err == nil {
		t.Fatal("accepted an event whose fields are in alphabetical order rather than the " +
			"order KERI serialises them")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("refused, but not with a fault this suite can read: %v", err)
	}
	if !ve.Has(FaultFieldOrder) {
		t.Fatalf("refused, but without naming the ordering as the problem: %v", err)
	}
}
