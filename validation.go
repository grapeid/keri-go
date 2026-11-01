package keri

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Validation: deciding whether a key history is really this identity's history.
//
// Everything else in this package produces bytes. This produces a verdict, and
// the verdict is what decides whether a stranger is trusted — so the property
// that matters most is that it REFUSES correctly. A validator that accepts a
// forged event is worse than no validator at all, because every layer above it
// then treats the result as checked.
//
// Three design choices are worth stating, because each was a decision rather
// than the obvious thing:
//
//  1. A refusal reports EVERY fault it found, not the first. Real tampering
//     usually breaks more than one rule at once — altering a key count both
//     changes the digest and can break the parsedThreshold — and a validator that
//     stops at the first fault tells the reader of a log which check happened
//     to run first rather than what is wrong with the event.
//
//  2. Faults carry a machine-readable kind AND a plain-words detail. Somebody
//     reading a refusal in a log needs to know whether they hit a bug or an
//     attack, and "invalid event" tells them neither.
//
//  3. Nothing is ever re-serialised in order to check it. The identifier is a
//     digest of the exact bytes, and Go marshals a map alphabetically, so a
//     round trip through map[string]interface{} would silently reorder the
//     event and produce a digest nothing else in the world agrees with. Every
//     check here works from the raw bytes, and the digest is re-derived by
//     overwriting the identifier IN PLACE with a placeholder of the same width.
//
// There is no network here and no clock: everything needed to decide is in the
// bytes handed in. That is deliberate — this has to run on a phone that is
// offline.

// FaultKind names what was wrong, in a form a program can branch on.
//
// The kinds are stable strings rather than integers so a refusal survives a log
// file, a wire format, or a bug report without a lookup table.
type FaultKind string

const (
	// FaultMalformed is bytes that are not a readable KERI event at all.
	FaultMalformed FaultKind = "malformed"
	// FaultVersionLength is a version string that declares a size the event
	// does not have — the signal that something was appended or removed.
	FaultVersionLength FaultKind = "version-length"
	// FaultUnknownIlk is an event type this validator does not know.
	FaultUnknownIlk FaultKind = "unknown-ilk"
	// FaultUndefinedField is a field the schema does not define.
	FaultUndefinedField FaultKind = "undefined-field"
	// FaultMissingField is a field the schema requires and the event omits.
	FaultMissingField FaultKind = "missing-field"
	// FaultFieldOrder is the right fields in the wrong order. Order is part of
	// the serialisation the digest covers, so this is a real difference and not
	// a cosmetic one.
	FaultFieldOrder FaultKind = "field-order"
	// FaultSAIDMismatch is an event whose contents do not digest to the
	// identifier it claims.
	FaultSAIDMismatch FaultKind = "said-mismatch"
	// FaultDerivationMismatch is an identifier that does not match how the
	// event says it was derived — a self-addressing prefix that is not the
	// event's digest, or a basic prefix that is not the event's key.
	FaultDerivationMismatch FaultKind = "derivation-mismatch"
	// FaultThresholdExceedsKeys is a signing parsedThreshold larger than the number
	// of keys supplied, which can never be met.
	FaultThresholdExceedsKeys FaultKind = "parsedThreshold-exceeds-keys"
	// FaultTOADExceedsWitnesses is a witness parsedThreshold larger than the number
	// of witnesses designated.
	FaultTOADExceedsWitnesses FaultKind = "toad-exceeds-witnesses"
	// FaultSequenceSkip is a sequence number that does not follow its
	// predecessor.
	FaultSequenceSkip FaultKind = "sequence-skip"
	// FaultPriorDigestMismatch is a prior-event digest that is not the digest
	// of the previous event.
	FaultPriorDigestMismatch FaultKind = "prior-digest-mismatch"
	// FaultIdentifierMismatch is an event attributed to a different identity
	// than the log it arrived in.
	FaultIdentifierMismatch FaultKind = "identifier-mismatch"
	// FaultKeyNotPrecommitted is a rotation whose keys could not open enough
	// of the previous establishment event's commitments to meet its next
	// threshold, even if every one of them signed.
	FaultKeyNotPrecommitted FaultKind = "key-not-precommitted"
	// FaultWitnessListInvalid is a witness list that cannot be right: a
	// rotation cutting a witness that is not there or adding one that already
	// is, an entry that is not a canonical non-transferable identifier, or one
	// witness named twice.
	FaultWitnessListInvalid FaultKind = "witness-list-invalid"
	// FaultKeyListInvalid is an establishment event that lists one signing key
	// twice in k, or one next-key digest twice in n, so that one key could
	// count twice toward a threshold.
	FaultKeyListInvalid FaultKind = "key-list-invalid"
	// FaultReceiptSignature is a receipt whose signature does not verify —
	// including one whose signature or signer cannot be read at all, since in
	// neither case has a witness vote been demonstrated.
	FaultReceiptSignature FaultKind = "receipt-signature"
	// FaultUndesignatedWitness is a receipt from an identifier the event never
	// named as a witness.
	FaultUndesignatedWitness FaultKind = "undesignated-witness"
	// FaultReceiptTarget is a receipt that names a different event than the one
	// it was checked against.
	FaultReceiptTarget FaultKind = "receipt-target"
	// FaultStreamTruncated is a stream that ends before its attached material
	// is complete.
	FaultStreamTruncated FaultKind = "stream-truncated"
	// FaultStreamMalformed is attached material that is not readable CESR.
	FaultStreamMalformed FaultKind = "stream-malformed"
	// FaultSignatureInvalid is a controller signature that names a key outside
	// the key list, or whose key cannot be read. A signature that simply does
	// not verify is dropped rather than reported: it attests nothing, the rest
	// are judged without it, and if they fall short the refusal is
	// FaultThresholdNotMet.
	FaultSignatureInvalid FaultKind = "signature-invalid"
	// FaultThresholdNotMet is a signature set that does not meet the parsedThreshold
	// the identity committed to.
	FaultThresholdNotMet FaultKind = "parsedThreshold-not-met"
	// FaultPlaceTaken is an event at a place a verified log already holds a
	// different event at, which is not a recovery rotation that may replace
	// it. Two such events, each correctly signed, are duplicity, except where
	// the second is a delegated rotation: that is refused because whether it
	// may replace the first turns on the delegator's log, not because it is
	// duplicitous.
	FaultPlaceTaken FaultKind = "place-taken"
)

// Fault is one reason something was refused.
type Fault struct {
	// Kind is what rule was broken.
	Kind FaultKind
	// Where names the event or attachment the fault is in, so a refusal in a
	// long log points at a place rather than at the log.
	Where string
	// Detail says what is wrong in plain words.
	Detail string
}

func (f Fault) String() string {
	if f.Where == "" {
		return fmt.Sprintf("%s: %s", f.Kind, f.Detail)
	}
	return fmt.Sprintf("%s (%s): %s", f.Kind, f.Where, f.Detail)
}

// ValidationError is a refusal, carrying every fault found.
//
// Every fault rather than the first, because tampering usually breaks several
// rules at once and reporting only one makes the reader guess at the rest.
type ValidationError struct {
	Faults []Fault
}

func (e *ValidationError) Error() string {
	switch len(e.Faults) {
	case 0:
		// Never constructed empty; guarded so a bug here cannot present itself
		// as a refusal with no reason, which is the least useful thing a
		// validator can say.
		return "refused, but no reason was recorded — this is a bug in the validator"
	case 1:
		return "refused: " + e.Faults[0].String()
	}
	parts := make([]string, 0, len(e.Faults))
	for _, f := range e.Faults {
		parts = append(parts, f.String())
	}
	return fmt.Sprintf("refused, %d faults: %s", len(e.Faults), strings.Join(parts, "; "))
}

// Has reports whether a fault of this kind was found.
func (e *ValidationError) Has(kind FaultKind) bool {
	for _, f := range e.Faults {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// faults collects faults during a validation pass.
type faults struct {
	list  []Fault
	where string
}

func (fs *faults) at(where string) { fs.where = where }

func (fs *faults) add(kind FaultKind, format string, args ...interface{}) {
	fs.list = append(fs.list, Fault{
		Kind:   kind,
		Where:  fs.where,
		Detail: fmt.Sprintf(format, args...),
	})
}

func (fs *faults) err() error {
	if len(fs.list) == 0 {
		return nil
	}
	return &ValidationError{Faults: fs.list}
}

// -----------------------------------------------------------------------------
// Reading an event without re-serialising it
// -----------------------------------------------------------------------------

// jsonField is one top-level field of an event, with the exact byte span its
// value occupies.
//
// The span is the point of this type. Re-deriving an identifier means replacing
// the identifier's value with a placeholder and hashing the result, and the only
// way to do that without changing anything else is to overwrite those bytes
// where they lie.
type jsonField struct {
	Name       string
	Value      []byte
	ValueStart int
	ValueEnd   int // exclusive
}

// scanFields reads the top-level fields of a JSON object in the order they
// appear.
//
// Hand-written rather than delegated to encoding/json because the order and the
// byte offsets are both load-bearing and neither survives a decode into a Go
// map.
func scanFields(raw []byte) ([]jsonField, error) {
	i := skipSpace(raw, 0)
	if i >= len(raw) || raw[i] != '{' {
		return nil, fmt.Errorf("an event must be a JSON object")
	}
	i++
	var out []jsonField
	i = skipSpace(raw, i)
	if i < len(raw) && raw[i] == '}' {
		return out, nil
	}
	for {
		i = skipSpace(raw, i)
		if i >= len(raw) || raw[i] != '"' {
			return nil, fmt.Errorf("expected a field name at byte %d", i)
		}
		nameEnd, err := scanString(raw, i)
		if err != nil {
			return nil, err
		}
		var name string
		if err := json.Unmarshal(raw[i:nameEnd], &name); err != nil {
			return nil, fmt.Errorf("field name at byte %d is not readable: %w", i, err)
		}
		i = skipSpace(raw, nameEnd)
		if i >= len(raw) || raw[i] != ':' {
			return nil, fmt.Errorf("field %q is not followed by a value", name)
		}
		i = skipSpace(raw, i+1)
		valEnd, err := skipValue(raw, i)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", name, err)
		}
		out = append(out, jsonField{
			Name:       name,
			Value:      raw[i:valEnd],
			ValueStart: i,
			ValueEnd:   valEnd,
		})
		i = skipSpace(raw, valEnd)
		if i >= len(raw) {
			return nil, fmt.Errorf("the event ends before its closing brace")
		}
		switch raw[i] {
		case ',':
			i++
		case '}':
			return out, nil
		default:
			return nil, fmt.Errorf("unexpected %q after field %q", raw[i], name)
		}
	}
}

func skipSpace(raw []byte, i int) int {
	for i < len(raw) {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// scanString returns the index just past a JSON string starting at i.
func scanString(raw []byte, i int) (int, error) {
	if i >= len(raw) || raw[i] != '"' {
		return 0, fmt.Errorf("expected a string at byte %d", i)
	}
	for j := i + 1; j < len(raw); j++ {
		switch raw[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, fmt.Errorf("a string beginning at byte %d is never closed", i)
}

// skipValue returns the index just past the JSON value starting at i.
func skipValue(raw []byte, i int) (int, error) {
	if i >= len(raw) {
		return 0, fmt.Errorf("a value is missing at the end of the event")
	}
	switch raw[i] {
	case '"':
		return scanString(raw, i)
	case '{', '[':
		open, close := raw[i], byte('}')
		if open == '[' {
			close = ']'
		}
		depth := 0
		for j := i; j < len(raw); j++ {
			switch raw[j] {
			case '"':
				end, err := scanString(raw, j)
				if err != nil {
					return 0, err
				}
				j = end - 1
			case open:
				depth++
			case close:
				depth--
				if depth == 0 {
					return j + 1, nil
				}
			}
		}
		return 0, fmt.Errorf("a %q beginning at byte %d is never closed", open, i)
	default:
		for j := i; j < len(raw); j++ {
			switch raw[j] {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				if j == i {
					return 0, fmt.Errorf("expected a value at byte %d", i)
				}
				return j, nil
			}
		}
		return len(raw), nil
	}
}

// -----------------------------------------------------------------------------
// The event, as read
// -----------------------------------------------------------------------------

// Derivation is how an identifier was made from its inception event.
//
// Both kinds are real and both are in use, which is the whole point of naming
// them: an implementation that assumes the identifier is always the digest
// breaks every single-key identity that already exists, and one that assumes it
// is always the key cannot make a multi-signature identity at all.
type Derivation string

const (
	// DerivationBasic: the identifier IS the public key. Single-key inception
	// only, and the identifier reads D… (or B… when the key can never rotate).
	DerivationBasic Derivation = "basic"
	// DerivationSelfAddressing: the identifier IS the digest of the inception
	// event, and reads E….
	DerivationSelfAddressing Derivation = "self-addressing"
)

// Event is a KERI event as it was read from the wire.
//
// Raw is kept because it, and not any field here, is what the identifier
// digests and what a signature covers. Everything else is a convenience for
// checks that do not need the bytes.
type Event struct {
	Raw        []byte
	Fields     []jsonField
	Ilk        string
	Identifier string
	SAID       string
	SN         uint64
	PriorSAID  string
	Keys       []string
	NextDigest []string
	Witnesses  []string // b, on an inception
	WitnessCut []string // br, on a rotation
	WitnessAdd []string // ba, on a rotation
	Delegator  string
	// Thresholds are kept in parsed form; nil when the ilk does not carry one.
	SigThreshold  *parsedThreshold
	NextThreshold *parsedThreshold
	TOAD          uint64
	HasTOAD       bool
}

// Establishment reports whether this event changes the identity's keys — the
// events a later rotation must chain its authority to.
func (e *Event) Establishment() bool {
	switch e.Ilk {
	case "icp", "rot", "dip", "drt":
		return true
	}
	return false
}

// Derivation says how this event's identifier was made.
func (e *Event) Derivation() Derivation {
	if strings.HasPrefix(e.Identifier, CodeBlake3_256) {
		return DerivationSelfAddressing
	}
	return DerivationBasic
}

// keriSchema is the fields each event type carries, in the order it carries
// them.
//
// Order is protocol, not style: the version string declares the length of what
// follows and the identifier is a digest of the whole thing, so a reordered
// event is a different event. Listed explicitly rather than derived from a
// struct so that adding a field is a visible change to a table somebody reviews.
var keriSchema = map[string][]string{
	"icp": {"v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"},
	"rot": {"v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"},
	"ixn": {"v", "t", "d", "i", "s", "p", "a"},
	"dip": {"v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"},
	"drt": {"v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"},
	"rct": {"v", "t", "d", "i", "s"},
}

// ParseEvent reads an event's bytes into the fields a check needs.
//
// It does NOT decide whether the event is acceptable — that is ValidateEvent.
// The split matters: parsing failing means "these bytes are not an event",
// which is a different statement from "this event is not allowed", and a caller
// that cannot tell them apart cannot tell a corrupt file from an attack.
func ParseEvent(raw []byte) (*Event, error) {
	fields, err := scanFields(raw)
	if err != nil {
		return nil, fmt.Errorf("not a readable event: %w", err)
	}
	ev := &Event{Raw: raw, Fields: fields}
	for _, f := range fields {
		switch f.Name {
		case "t":
			ev.Ilk, _ = jsonString(f.Value)
		case "d":
			ev.SAID, _ = jsonString(f.Value)
		case "i":
			ev.Identifier, _ = jsonString(f.Value)
		case "p":
			ev.PriorSAID, _ = jsonString(f.Value)
		case "di":
			ev.Delegator, _ = jsonString(f.Value)
		case "s":
			s, ok := jsonString(f.Value)
			if !ok {
				return nil, fmt.Errorf("the sequence number is not a string")
			}
			n, perr := canonicalHex(s)
			if perr != nil {
				return nil, fmt.Errorf("sequence number: %w", perr)
			}
			ev.SN = n
		case "k":
			ev.Keys, _ = jsonStrings(f.Value)
		case "n":
			ev.NextDigest, _ = jsonStrings(f.Value)
		case "b":
			ev.Witnesses, _ = jsonStrings(f.Value)
		case "br":
			ev.WitnessCut, _ = jsonStrings(f.Value)
		case "ba":
			ev.WitnessAdd, _ = jsonStrings(f.Value)
		case "bt":
			// Refused rather than skipped. An unreadable witness threshold
			// left absent reads as "no threshold stated", and a reader that
			// inherits the previous one, which is zero at inception, would
			// take an event as witnessed that no witness has receipted.
			s, ok := jsonString(f.Value)
			if !ok {
				return nil, fmt.Errorf("the witness threshold is not a string")
			}
			n, perr := canonicalHex(s)
			if perr != nil {
				return nil, fmt.Errorf("witness threshold: %w", perr)
			}
			ev.TOAD, ev.HasTOAD = n, true
		case "kt":
			t, perr := parseThreshold(f.Value)
			if perr != nil {
				return nil, fmt.Errorf("signing threshold: %w", perr)
			}
			ev.SigThreshold = t
		case "nt":
			t, perr := parseThreshold(f.Value)
			if perr != nil {
				return nil, fmt.Errorf("next-key threshold: %w", perr)
			}
			ev.NextThreshold = t
		}
	}
	if ev.Ilk == "" {
		return nil, fmt.Errorf("the event does not say what type it is")
	}
	return ev, nil
}

// canonicalHex reads a count written as KERI writes one: lowercase
// hexadecimal with no leading zeros, "0" itself included. strconv alone also
// takes uppercase digits and leading zeros, so "a", "A" and "0a" would be one
// number spelled three ways; only the first is read.
func canonicalHex(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 16, 64)
	if err != nil || strconv.FormatUint(n, 16) != s {
		return 0, fmt.Errorf("%q is not a count in lowercase hexadecimal without leading zeros", s)
	}
	return n, nil
}

func jsonString(raw []byte) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func jsonStrings(raw []byte) ([]string, bool) {
	var s []string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	return s, true
}

// -----------------------------------------------------------------------------
// Re-deriving the identifier
// -----------------------------------------------------------------------------

// ComputeSAID re-derives an event's self-addressing identifier from its bytes.
//
// The procedure, stated because getting any part of it wrong yields a plausible
// answer that no other implementation agrees with: the identifier field is
// overwritten with placeholder characters of EXACTLY the final width, so the
// length the version string declares stays true, and the digest is taken over
// that. For a self-addressing inception the prefix field is a copy of the same
// identifier and is blanked too; for every other event the prefix is an
// identifier that already existed and is left alone.
//
// The event's own d field is never trusted as input, since checking it is the
// entire point.
func ComputeSAID(raw []byte) (string, error) {
	ev, err := ParseEvent(raw)
	if err != nil {
		return "", err
	}
	return computeSAID(ev)
}

func computeSAID(ev *Event) (string, error) {
	blank := map[string]bool{"d": true}
	if (ev.Ilk == "icp" || ev.Ilk == "dip") && strings.HasPrefix(ev.Identifier, CodeBlake3_256) {
		blank["i"] = true
	}
	dummy := make([]byte, len(ev.Raw))
	copy(dummy, ev.Raw)
	blanked := 0
	for _, f := range ev.Fields {
		if !blank[f.Name] {
			continue
		}
		// The value must already be a quoted string of the placeholder width.
		// If it is not, substituting would change the event's length and the
		// version string would then declare a size the bytes do not have.
		if f.ValueEnd-f.ValueStart != saidPlaceholderLen+2 ||
			dummy[f.ValueStart] != '"' || dummy[f.ValueEnd-1] != '"' {
			return "", fmt.Errorf("the %q field is not a %d-character identifier, so the "+
				"event's declared length cannot be reproduced", f.Name, saidPlaceholderLen)
		}
		for i := f.ValueStart + 1; i < f.ValueEnd-1; i++ {
			dummy[i] = '#'
		}
		blanked++
	}
	if blanked != len(blank) {
		return "", fmt.Errorf("the event is missing an identifier field, so its digest "+
			"cannot be reproduced (blanked %d of %d)", blanked, len(blank))
	}
	return Blake3SAID(dummy)
}

// -----------------------------------------------------------------------------
// Validating one event
// -----------------------------------------------------------------------------

// ValidateEvent checks everything about an event that can be decided from the
// event alone.
//
// That is: it is well formed, it carries exactly the fields its type defines in
// the order the protocol serialises them, its version string tells the truth
// about its length, its contents digest to the identifier it claims, and its
// thresholds are ones that could ever be met. Anything that needs a predecessor
// — sequence, prior digest, pre-rotation — is ValidateKEL's job, because it
// cannot be answered without one.
func ValidateEvent(raw []byte) error {
	fs := &faults{}
	validateEvent(fs, raw)
	return fs.err()
}

func validateEvent(fs *faults, raw []byte) *Event {
	ev, err := ParseEvent(raw)
	if err != nil {
		fs.add(FaultMalformed, "%v", err)
		return nil
	}
	fs.at(fmt.Sprintf("%s at sn %d", ev.Ilk, ev.SN))

	schema, known := keriSchema[ev.Ilk]
	if !known {
		fs.add(FaultUnknownIlk, "%q is not an event type this validator knows, so nothing "+
			"about it can be checked", ev.Ilk)
		return ev
	}
	checkSchema(fs, ev, schema)
	checkEventVersion(fs, ev)

	// A receipt's d names the event being receipted, not the receipt itself, so
	// the self-addressing check does not apply to it.
	if ev.Ilk != "rct" {
		checkEventSAID(fs, ev)
		checkDerivation(fs, ev)
	}
	checkThresholds(fs, ev)
	checkWitnessIdentifiers(fs, ev)
	checkKeyLists(fs, ev)
	return ev
}

func checkSchema(fs *faults, ev *Event, schema []string) {
	defined := make(map[string]bool, len(schema))
	for _, name := range schema {
		defined[name] = true
	}
	present := make(map[string]bool, len(ev.Fields))
	var order []string
	for _, f := range ev.Fields {
		if !defined[f.Name] {
			fs.add(FaultUndefinedField, "the event carries a field %q that a %s does not "+
				"define; two implementations reading this would disagree about what was "+
				"signed", f.Name, ev.Ilk)
			continue
		}
		if present[f.Name] {
			fs.add(FaultUndefinedField, "the field %q appears more than once", f.Name)
			continue
		}
		present[f.Name] = true
		order = append(order, f.Name)
	}
	var missing []string
	for _, name := range schema {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		fs.add(FaultMissingField, "a %s must carry %s, and this one does not",
			ev.Ilk, strings.Join(missing, ", "))
		return
	}
	// Order is compared only once every defined field is present, so a missing
	// field is reported as missing rather than as a reordering.
	expected := make([]string, 0, len(schema))
	for _, name := range schema {
		if present[name] {
			expected = append(expected, name)
		}
	}
	if strings.Join(order, ",") != strings.Join(expected, ",") {
		fs.add(FaultFieldOrder, "a %s serialises its fields as %s, and this one is %s; "+
			"field order is part of what the identifier digests, so this is a different "+
			"event", ev.Ilk, strings.Join(expected, " "), strings.Join(order, " "))
	}
}

func checkEventVersion(fs *faults, ev *Event) {
	if len(ev.Raw) < 6 || string(ev.Raw[:6]) != `{"v":"` {
		fs.add(FaultVersionLength, "the event does not begin with its version string, so "+
			"it is not canonical KERI serialisation")
		return
	}
	var vs string
	for _, f := range ev.Fields {
		if f.Name == "v" {
			vs, _ = jsonString(f.Value)
		}
	}
	if !versionPattern.MatchString(vs) {
		fs.add(FaultVersionLength, "the version string %q is not readable", vs)
		return
	}
	declared, err := strconv.ParseUint(vs[10:16], 16, 64)
	if err != nil {
		fs.add(FaultVersionLength, "the version string %q does not declare a size", vs)
		return
	}
	if declared != uint64(len(ev.Raw)) {
		fs.add(FaultVersionLength, "the version string declares %d bytes and the event is "+
			"%d, so something has been added to it or taken from it", declared, len(ev.Raw))
	}
}

func checkEventSAID(fs *faults, ev *Event) {
	want, err := computeSAID(ev)
	if err != nil {
		fs.add(FaultSAIDMismatch, "the event's identifier could not be re-derived: %v", err)
		return
	}
	if want != ev.SAID {
		fs.add(FaultSAIDMismatch, "the contents digest to %s but the event claims %s, so "+
			"these bytes are not the event that identifier names", want, ev.SAID)
	}
}

// checkDerivation holds the two ways an identifier is made to their own rules.
func checkDerivation(fs *faults, ev *Event) {
	switch ev.Ilk {
	case "icp", "dip":
		if ev.Derivation() == DerivationSelfAddressing {
			if ev.Identifier != ev.SAID {
				fs.add(FaultDerivationMismatch, "a self-addressing identifier IS the digest "+
					"of its inception event, but this event's identifier is %s and its digest "+
					"is %s", ev.Identifier, ev.SAID)
			}
			return
		}
		// Basic derivation: the identifier IS the key, so there can only be one.
		if len(ev.Keys) != 1 {
			fs.add(FaultDerivationMismatch, "the identifier %s is a public key rather than a "+
				"digest, which only a single-key inception can be, but this event carries %d "+
				"keys", ev.Identifier, len(ev.Keys))
			return
		}
		if ev.Identifier != ev.Keys[0] {
			fs.add(FaultDerivationMismatch, "a basic identifier IS its public key, but this "+
				"event's identifier is %s and its key is %s", ev.Identifier, ev.Keys[0])
		}
	}
}

func checkThresholds(fs *faults, ev *Event) {
	if ev.SigThreshold != nil {
		if bad, why := ev.SigThreshold.exceeds(len(ev.Keys)); bad {
			fs.add(FaultThresholdExceedsKeys, "the signing parsedThreshold could never be met: %s", why)
		}
	}
	if ev.NextThreshold != nil && len(ev.NextDigest) > 0 {
		// A next threshold of zero is how an identity is abandoned, with or
		// without commitments listed: no set of signatures meets zero, so no
		// rotation can follow. keripy accepts the event that says so, and so
		// does this. Any other next threshold must be reachable.
		zeroCount := !ev.NextThreshold.weighted && ev.NextThreshold.count == 0
		if bad, why := ev.NextThreshold.exceeds(len(ev.NextDigest)); bad && !zeroCount {
			fs.add(FaultThresholdExceedsKeys, "the next-key parsedThreshold could never be met: %s", why)
		}
	}
	if ev.HasTOAD {
		switch ev.Ilk {
		case "icp", "dip":
			if ev.TOAD > uint64(len(ev.Witnesses)) {
				fs.add(FaultTOADExceedsWitnesses, "the witness parsedThreshold is %d but only %d "+
					"witnesses are designated", ev.TOAD, len(ev.Witnesses))
			}
			if ev.TOAD == 0 && len(ev.Witnesses) > 0 {
				fs.add(FaultTOADExceedsWitnesses, "%d witnesses are designated but the "+
					"parsedThreshold is zero, so none of them would ever be required",
					len(ev.Witnesses))
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Validating a key event log
// -----------------------------------------------------------------------------

// ValidateKEL decides whether a sequence of events is really one identity's
// history, in the order given.
//
// Events are raw serialised bytes — [][]byte rather than []json.RawMessage on
// purpose. json.RawMessage invites a caller to treat an event as a JSON value
// to be re-encoded, and re-encoding is precisely what destroys an identifier:
// the field order is part of what the digest covers and Go sorts a map's keys.
// These are bytes that happen to be JSON, and the type says so.
//
// What it checks, beyond each event on its own:
//
//   - the log begins with an inception at sequence number zero
//   - every event names the same identity
//   - sequence numbers are contiguous, so nothing was inserted or dropped
//   - every event digests its predecessor, so nothing was substituted
//   - every rotation lists keys that could, by signing, open enough of the
//     previous establishment event's commitments to meet its next threshold.
//     Whether the keys that actually signed do is ValidateSignedKEL's
//     question, because it needs the signatures
//   - a rotation's witness changes refer to witnesses that are actually there
//
// Two things it deliberately does NOT check, stated here because a caller who
// mistook this verdict for either of them would be trusting something nobody
// checked:
//
//   - Signatures. An event's bytes do not carry them, and inventing a verdict
//     about a signature that was never supplied would be the most dangerous
//     thing this package could do. Use ValidateStream, or ValidateReceipts,
//     where the attachments are available.
//   - Delegation. A dip or drt is checked as an event and as a link in this
//     chain, but whether the DELEGATOR actually anchored it needs the
//     delegator's own key history, which is not among the arguments. Accepting
//     a delegated event here says the identity's own history is sound; it says
//     nothing about whether the delegation was authorised.
func ValidateKEL(events [][]byte) error {
	fs := &faults{}
	if len(events) == 0 {
		fs.add(FaultMalformed, "an empty log establishes no identity")
		return fs.err()
	}

	var state *KeyState
	for idx, raw := range events {
		ev := validateEvent(fs, raw)
		if ev == nil {
			// Nothing that follows can be chained to bytes that are not an
			// event, so stop rather than report a cascade of consequences.
			return fs.err()
		}
		fs.at(fmt.Sprintf("event %d (%s at sn %d)", idx, ev.Ilk, ev.SN))
		state = advance(fs, state, ev, nil, false).state
	}
	return fs.err()
}

// checkPrecommitment is what can be said about a rotation's pre-rotation
// without its signatures.
//
// The previous establishment event published DIGESTS of the keys that would
// come next, and a threshold over them. Whether a rotation is authorised turns
// on which of those commitments the keys that SIGNED it open, and only
// ValidateSignedKEL has the signatures. What can be decided here is the
// necessary half: if every key the rotation lists were to sign, the
// commitments they could open must meet the prior next threshold. A rotation
// that fails that can never be authorised by any set of signatures.
//
// Passing this is not authorisation. A rotation whose listed keys could open
// enough commitments, but which was signed by too few of them, passes here and
// is refused by ValidateSignedKEL.
//
// A rotation may also list keys the previous event never committed to (an
// augmented rotation). KERI allows it, and keripy accepts it, when the
// thresholds are met: such a key opens nothing and its signature counts toward
// the new signing threshold only. So it is not a fault here. What a builder
// chooses to emit is a narrower question, and never narrows what this accepts.
func checkPrecommitment(fs *faults, ev *Event, committed []string, th *parsedThreshold) {
	if len(ev.Keys) == 0 {
		fs.add(FaultKeyNotPrecommitted, "a rotation must present the keys it is rotating to")
		return
	}
	places := make(map[string][]int, len(committed))
	for i, d := range committed {
		places[d] = append(places[d], i)
	}
	openable := make(map[int]bool, len(ev.Keys))
	for _, key := range ev.Keys {
		digest, err := Blake3SAID([]byte(key))
		if err != nil {
			fs.add(FaultKeyNotPrecommitted, "the key %s could not be digested: %v", key, err)
			continue
		}
		for _, p := range places[digest] {
			openable[p] = true
		}
	}
	if !th.satisfiedBy(openable) {
		fs.add(FaultKeyNotPrecommitted, "even if every key it lists signed, the rotation "+
			"could open only %d of the %d keys the previous establishment event committed "+
			"to (%s), which does not meet the next threshold it set, so whoever holds "+
			"these keys cannot take over this identity", len(openable), len(committed),
			strings.Join(committed, ", "))
	}
}

// checkWitnessIdentifiers holds each witness list an event names to two rules:
// every entry is a non-transferable identifier in its one canonical spelling,
// and no witness is named twice, judged by its key rather than its text.
//
// A witness is counted toward the threshold, so one that can be named two ways
// can be counted twice. Comparing text alone does not stop that: two spellings
// of one key are different strings. Requiring the canonical spelling means each
// key has one string, and comparing keys says so outright.
//
// This refuses an event that names any other kind of witness — a transferable
// key, or a key on another curve — which used to validate with that witness's
// receipts simply never counted. A witness must be non-transferable, so a
// receipt can be checked from its identifier alone, and Ed25519 is the only
// curve this package verifies; an event whose witnesses can never be counted
// is refused rather than accepted with a threshold it cannot meet.
func checkWitnessIdentifiers(fs *faults, ev *Event) {
	lists := []struct {
		field string
		names []string
	}{{"b", ev.Witnesses}, {"br", ev.WitnessCut}, {"ba", ev.WitnessAdd}}
	for _, l := range lists {
		if err := noDuplicateWitnesses(l.names, "witness"); err != nil {
			fs.add(FaultWitnessListInvalid, "%s: %v", l.field, err)
		}
	}
}

// witnessKey is the key a witness identifier is made of, as a map key: the
// form in which two names for one witness are equal.
func witnessKey(aid string) (string, error) {
	pub, err := MatterRaw(CodeEd25519N, aid, ed25519.PublicKeySize)
	if err != nil {
		return "", err
	}
	return string(pub), nil
}

// checkWitnessChange holds a rotation's witness delta to the witnesses it
// changes: a cut must name a current witness, an add must not, and no witness
// may be both cut and added in one event. A cut-and-re-add changes nothing a
// peer can see, and the reference refuses it ("Intersecting cuts and adds"), as
// BuildRotation does; compared by key, as every witness comparison here is.
func checkWitnessChange(fs *faults, ev *Event, current []string) {
	cutKeys := make(map[string]bool, len(ev.WitnessCut))
	for _, w := range ev.WitnessCut {
		if k, err := witnessKey(w); err == nil {
			cutKeys[k] = true
		}
	}
	for _, w := range ev.WitnessAdd {
		if k, err := witnessKey(w); err == nil && cutKeys[k] {
			fs.add(FaultWitnessListInvalid, "the rotation both cuts and adds the witness "+
				"%s, which keripy refuses as intersecting cuts and adds", w)
		}
	}
	have := make(map[string]bool, len(current))
	for _, w := range current {
		have[w] = true
	}
	for _, w := range ev.WitnessCut {
		if !have[w] {
			fs.add(FaultWitnessListInvalid, "the rotation removes the witness %s, which is "+
				"not one of this identity's witnesses", w)
		}
		have[w] = false
	}
	for _, w := range ev.WitnessAdd {
		if have[w] {
			fs.add(FaultWitnessListInvalid, "the rotation adds the witness %s, which is "+
				"already designated", w)
		}
		have[w] = true
	}
}

func applyWitnessChange(current []string, ev *Event) []string {
	cut := make(map[string]bool, len(ev.WitnessCut))
	for _, w := range ev.WitnessCut {
		cut[w] = true
	}
	out := make([]string, 0, len(current)+len(ev.WitnessAdd))
	for _, w := range current {
		if !cut[w] {
			out = append(out, w)
		}
	}
	return append(out, ev.WitnessAdd...)
}

// -----------------------------------------------------------------------------
// Attachments
// -----------------------------------------------------------------------------

// A CESR stream is an event's bytes followed by counted groups of attached
// material — the signatures and receipts that make the event worth anything.
//
// Only what validation needs is implemented here: enough framing to say whether
// the attachments are complete and readable, and enough of the primitives to
// verify a signature. A group this does not understand is REFUSED rather than
// skipped, because skipping it would mean reporting "valid" about material that
// was never read.

const (
	counterControllerIdxSigs      = "-A"
	counterWitnessIdxSigs         = "-B"
	counterNonTransReceiptCouples = "-C"
	counterTransReceiptQuadruples = "-D"
	counterAttachedMaterial       = "-V"

	sizeIndexedSig = 88 // two-character code, then 86 characters of signature
	sizeCigar      = 88 // "0B" then 86
	sizePrefix     = 44 // one-character code, then 43
	sizeSeqner     = 24
)

// attachment is one group of attached material.
type attachment struct {
	Counter string
	Count   int
	// Sigs are indexed signatures, for the -A and -B groups.
	Sigs []indexedSig
	// Couples are witness identifier + signature, for the -C group.
	Couples []receiptCouple
}

// indexedSig is one indexed signature as read from an attachment.
//
// Index is the place in the current key list of the key that made it. Ondex,
// when HasOndex, is the place in the PRIOR establishment event's next-key
// commitments that the same key opens; a current-only code carries none, and
// such a signature counts toward the signing threshold but opens nothing.
type indexedSig struct {
	QB64     string
	Code     string
	Index    int
	Ondex    int
	HasOndex bool
	Raw      []byte
}

type receiptCouple struct {
	Signer string
	Sig    string
}

// splitStream separates the leading event from whatever is attached to it.
func splitStream(raw []byte) (event []byte, attached []byte, err error) {
	depth, inStr, esc := 0, false, false
	for i, b := range raw {
		if inStr {
			switch {
			case esc:
				esc = false
			case b == '\\':
				esc = true
			case b == '"':
				inStr = false
			}
			continue
		}
		switch b {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return raw[:i+1], raw[i+1:], nil
			}
		}
	}
	return nil, nil, fmt.Errorf("the stream does not begin with a complete event")
}

// parseAttachments reads the counted groups following an event.
//
// Every failure here is a refusal. A stream that ends mid-primitive looks
// exactly like one carrying fewer signatures, and treating a missing signature
// as absent-by-design is how an unwitnessed event gets accepted.
func parseAttachments(attached []byte) ([]attachment, error) {
	s := string(attached)
	var out []attachment
	for len(s) > 0 {
		if len(s) < 4 {
			return nil, fmt.Errorf("the stream ends after %d characters, which is not a "+
				"complete attachment counter", len(s))
		}
		code := s[:2]
		count, err := b64Int(s[2:4])
		if err != nil {
			return nil, fmt.Errorf("the attachment counter %q is not readable: %w", s[:4], err)
		}
		s = s[4:]
		group := attachment{Counter: code, Count: count}
		switch code {
		case counterAttachedMaterial:
			// The count is in quadlets: four characters each. The body is
			// another sequence of groups.
			size := count * 4
			if len(s) < size {
				return nil, fmt.Errorf("the attachment group %q declares %d characters and "+
					"only %d remain, so the stream ends before the attached material is "+
					"complete", code, size, len(s))
			}
			inner, err := parseAttachments([]byte(s[:size]))
			if err != nil {
				return nil, err
			}
			out = append(out, inner...)
			s = s[size:]
			continue
		case counterControllerIdxSigs, counterWitnessIdxSigs:
			sigs, used, err := readIndexedSigs(code, s, count)
			if err != nil {
				return nil, err
			}
			group.Sigs = sigs
			s = s[used:]
		case counterNonTransReceiptCouples:
			for i := 0; i < count; i++ {
				need := sizePrefix + sizeCigar
				if len(s) < need {
					return nil, fmt.Errorf("the attachment group %q promises %d receipts and "+
						"the stream ends %d characters into receipt %d, so the attached "+
						"material is incomplete", code, count, len(s), i+1)
				}
				group.Couples = append(group.Couples, receiptCouple{
					Signer: s[:sizePrefix],
					Sig:    s[sizePrefix : sizePrefix+sizeCigar],
				})
				s = s[need:]
			}
		case counterTransReceiptQuadruples:
			// Identifier, sequence number, event digest, signature. Sized from
			// the CESR tables; no vector in this suite exercises it, which is
			// why it is stated here rather than assumed silently elsewhere.
			used, err := transReceiptQuadruplesWidth(code, s, count)
			if err != nil {
				return nil, err
			}
			s = s[used:]
		default:
			return nil, fmt.Errorf("the attachment group %q is one this validator does not "+
				"know how to read, so the rest of the stream cannot be trusted", code)
		}
		out = append(out, group)
	}
	return out, nil
}

// Indexed Ed25519 signature codes, as keripy 1.3.6's indexing table defines
// them. The code says which lists the signature's places refer to and how wide
// they are:
//
//	code  width  index      prior-next place (ondex)
//	A     88     1 char     the same as the index
//	B     88     1 char     none: the current list only
//	2A    92     2 chars    2 chars of its own
//	2B    92     2 chars    none; its two ondex characters must be zero
//
// A key whose place in k differs from the place it opens in the prior n needs
// 2A; written as A it would be checked against the wrong commitment.
const (
	codeIdxSig       = "A"
	codeIdxCrtSig    = "B"
	codeIdxBigSig    = "2A"
	codeIdxBigCrtSig = "2B"

	sizeIndexedBigSig = 92 // two-character code, two of index, two of ondex, then 86
)

// indexedSigWidth is how many characters the indexed signature at the start of
// s occupies, read from its code. A code this package does not know is
// refused, because guessing its width would read whatever follows from the
// wrong offset.
func indexedSigWidth(s string) (int, error) {
	switch {
	case strings.HasPrefix(s, codeIdxBigSig), strings.HasPrefix(s, codeIdxBigCrtSig):
		return sizeIndexedBigSig, nil
	case strings.HasPrefix(s, codeIdxSig), strings.HasPrefix(s, codeIdxCrtSig):
		return sizeIndexedSig, nil
	}
	return 0, fmt.Errorf("%.2q is not an Ed25519 indexed signature code", s)
}

// readIndexedSigs reads count indexed signatures from the front of s and
// returns them with the number of characters they occupied.
func readIndexedSigs(code, s string, count int) ([]indexedSig, int, error) {
	var out []indexedSig
	used := 0
	for i := 0; i < count; i++ {
		rest := s[used:]
		if rest == "" {
			return nil, 0, fmt.Errorf("the attachment group %q promises %d signatures "+
				"and the stream ends before signature %d, so the attached material is "+
				"incomplete", code, count, i+1)
		}
		width, err := indexedSigWidth(rest)
		if err != nil {
			return nil, 0, err
		}
		if len(rest) < width {
			return nil, 0, fmt.Errorf("the attachment group %q promises %d signatures "+
				"and the stream ends %d characters into signature %d, so the "+
				"attached material is incomplete", code, count, len(rest), i+1)
		}
		sig, err := readIndexedSig(rest[:width])
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sig)
		used += width
	}
	return out, used, nil
}

// transReceiptQuadruplesWidth measures count transferable receipt quadruples
// at the front of s: an identifier, a sequence number and an event digest of
// fixed width, then an indexed signature whose width comes from its own code.
func transReceiptQuadruplesWidth(code, s string, count int) (int, error) {
	const fixed = sizePrefix + sizeSeqner + sizePrefix
	used := 0
	for i := 0; i < count; i++ {
		if len(s)-used < fixed {
			return 0, fmt.Errorf("the attachment group %q promises %d receipts and "+
				"the stream ends %d characters into receipt %d", code, count, len(s)-used, i+1)
		}
		used += fixed
		_, n, err := readIndexedSigs(code, s[used:], 1)
		if err != nil {
			return 0, err
		}
		used += n
	}
	return used, nil
}

func readIndexedSig(qb64 string) (indexedSig, error) {
	width, err := indexedSigWidth(qb64)
	if err != nil {
		return indexedSig{}, err
	}
	if len(qb64) != width {
		return indexedSig{}, fmt.Errorf("an indexed signature with code %.2q is %d characters, "+
			"this one is %d", qb64, width, len(qb64))
	}
	sig := indexedSig{QB64: qb64}
	var codeLen int
	if width == sizeIndexedBigSig {
		sig.Code, codeLen = qb64[:2], 6
		if sig.Index, err = b64Int(qb64[2:4]); err != nil {
			return indexedSig{}, fmt.Errorf("the signature's index is not readable: %w", err)
		}
		ondex, err := b64Int(qb64[4:6])
		if err != nil {
			return indexedSig{}, fmt.Errorf("the signature's prior-next place is not "+
				"readable: %w", err)
		}
		if sig.Code == codeIdxBigSig {
			sig.Ondex, sig.HasOndex = ondex, true
		} else if ondex != 0 {
			// The reference refuses this, so it is refused here: a current-only
			// signature has no second place, and a non-zero one would be a
			// second spelling of the same signature.
			return indexedSig{}, fmt.Errorf("a current-only signature (%s) carries no "+
				"prior-next place, and this one carries %d", codeIdxBigCrtSig, ondex)
		}
	} else {
		sig.Code, codeLen = qb64[:1], 2
		if sig.Index, err = b64Int(qb64[1:2]); err != nil {
			return indexedSig{}, fmt.Errorf("the signature's index is not readable: %w", err)
		}
		if sig.Code == codeIdxSig {
			sig.Ondex, sig.HasOndex = sig.Index, true
		}
	}
	raw, err := MatterRaw(qb64[:codeLen], qb64, ed25519.SignatureSize)
	if err != nil {
		return indexedSig{}, fmt.Errorf("the attached signature is not readable: %w", err)
	}
	sig.Raw = raw
	return sig, nil
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func b64Int(s string) (int, error) {
	n := 0
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(b64Alphabet, s[i])
		if v < 0 {
			return 0, fmt.Errorf("%q is not base64url", s)
		}
		n = n*64 + v
	}
	return n, nil
}

// -----------------------------------------------------------------------------
// Validating a stream
// -----------------------------------------------------------------------------

// ValidateStream checks an event with its attachments as it arrives on the wire.
//
// The event is validated as usual, the attachments must be complete, and — when
// the event is an establishment event, which carries its own keys — the attached
// controller signatures must verify against those keys and meet the event's own
// signing parsedThreshold. An interaction event's keys come from an earlier
// establishment event, so its signatures cannot be checked without the log;
// ValidateSignedKEL does that.
func ValidateStream(raw []byte) error {
	fs := &faults{}
	event, attached, err := splitStream(raw)
	if err != nil {
		fs.add(FaultMalformed, "%v", err)
		return fs.err()
	}
	ev := validateEvent(fs, event)
	if ev == nil {
		return fs.err()
	}
	fs.at(fmt.Sprintf("%s at sn %d", ev.Ilk, ev.SN))
	groups, err := parseAttachments(attached)
	if err != nil {
		fs.add(FaultStreamTruncated, "%v", err)
		return fs.err()
	}
	if ev.Establishment() {
		verifyControllerSigs(fs, ev, groups)
	}
	return fs.err()
}

func verifyControllerSigs(fs *faults, ev *Event, groups []attachment) {
	verifyAgainstKeyState(fs, ev, groups, ev.Keys, ev.SigThreshold)
}

// -----------------------------------------------------------------------------
// Validating receipts
// -----------------------------------------------------------------------------

// ValidateReceipts checks a witness receipt stream against the event it covers.
//
// A receipt is a witness saying "I saw this event, and this is the one I saw".
// Two things make that worth anything and both are checked here: the signature
// must verify under the witness's own identifier, and the witness must be one
// the identity designated. Dropping either check hands an attacker the toad —
// they either forge votes or bring their own witnesses.
//
// designated may be nil, in which case the witnesses named by the event itself
// are used. Passing them explicitly is for the case where the event's witness
// list has since been changed by a rotation.
func ValidateReceipts(stream []byte, event []byte, designated []string) error {
	fs := &faults{}

	ev := validateEvent(fs, event)
	if ev == nil {
		return fs.err()
	}
	if designated == nil {
		designated = ev.Witnesses
	}
	allowed := make(map[string]bool, len(designated))
	for _, w := range designated {
		allowed[w] = true
	}

	body, attached, err := splitStream(stream)
	if err != nil {
		fs.add(FaultMalformed, "%v", err)
		return fs.err()
	}
	rct := validateEvent(fs, body)
	if rct == nil {
		return fs.err()
	}
	fs.at("receipt")
	if rct.Ilk != "rct" {
		fs.add(FaultReceiptTarget, "a receipt stream carries a rct, and this one carries a %s",
			rct.Ilk)
		return fs.err()
	}
	if rct.SAID != ev.SAID {
		fs.add(FaultReceiptTarget, "the receipt covers the event %s and it was checked "+
			"against %s, so it says nothing about this event", rct.SAID, ev.SAID)
	}
	if rct.Identifier != ev.Identifier {
		fs.add(FaultReceiptTarget, "the receipt names the identity %s and the event belongs "+
			"to %s", rct.Identifier, ev.Identifier)
	}
	if rct.SN != ev.SN {
		fs.add(FaultReceiptTarget, "the receipt is for sequence number %d and the event is "+
			"at %d", rct.SN, ev.SN)
	}

	groups, err := parseAttachments(attached)
	if err != nil {
		fs.add(FaultStreamTruncated, "%v", err)
		return fs.err()
	}

	seen := 0
	for _, g := range groups {
		if g.Counter != counterNonTransReceiptCouples {
			continue
		}
		for i, couple := range g.Couples {
			fs.at(fmt.Sprintf("receipt %d", i+1))
			seen++
			// A witness is non-transferable, so its identifier IS its verifying
			// key: anyone holding the key event can check the signature with
			// nothing else. If the identifier cannot be read, the receipt has
			// demonstrated nothing — and it is NOT reported as coming from an
			// undesignated witness, because we cannot say which witness was
			// meant.
			pub, err := MatterRaw(CodeEd25519N, couple.Signer, ed25519.PublicKeySize)
			if err != nil {
				fs.add(FaultReceiptSignature, "the receipt's signer %q is not a readable "+
					"non-transferable identifier (%v), so its signature cannot be verified "+
					"under any witness", couple.Signer, err)
				continue
			}
			if !allowed[couple.Signer] {
				fs.add(FaultUndesignatedWitness, "the receipt is signed by %s, which is not "+
					"one of the witnesses this identity designated (%s); only designated "+
					"witnesses count toward the parsedThreshold", couple.Signer,
					strings.Join(designated, ", "))
				continue
			}
			sig, err := MatterRaw(CodeEd25519Sig, couple.Sig, ed25519.SignatureSize)
			if err != nil {
				fs.add(FaultReceiptSignature, "the signature attached for witness %s is not "+
					"readable: %v", couple.Signer, err)
				continue
			}
			if !ed25519.Verify(pub, ev.Raw, sig) {
				fs.add(FaultReceiptSignature, "the signature attached for witness %s does not "+
					"verify over this event, so that witness never receipted it",
					couple.Signer)
			}
		}
	}
	fs.at("receipt")
	if seen == 0 {
		fs.add(FaultReceiptSignature, "the receipt stream carries no witness signature at all")
	}
	return fs.err()
}

// ReceiptsMeetThreshold reports how many DESIGNATED witnesses have validly
// receipted an event, and whether that meets the event's own parsedThreshold.
//
// Separate from ValidateReceipts because "this receipt is genuine" and "enough
// witnesses have signed" are different questions, and a caller that conflates
// them either rejects a partly-witnessed event it should hold, or accepts one
// it should not.
func ReceiptsMeetThreshold(stream []byte, event []byte, designated []string) (count int, met bool, err error) {
	ev, perr := ParseEvent(event)
	if perr != nil {
		return 0, false, perr
	}
	if designated == nil {
		designated = ev.Witnesses
	}
	allowed := make(map[string]bool, len(designated))
	for _, w := range designated {
		allowed[w] = true
	}
	_, attached, serr := splitStream(stream)
	if serr != nil {
		return 0, false, serr
	}
	groups, aerr := parseAttachments(attached)
	if aerr != nil {
		return 0, false, aerr
	}
	counted := make(map[string]bool)
	for _, g := range groups {
		if g.Counter != counterNonTransReceiptCouples {
			continue
		}
		for _, couple := range g.Couples {
			if !allowed[couple.Signer] {
				continue
			}
			pub, err := MatterRaw(CodeEd25519N, couple.Signer, ed25519.PublicKeySize)
			if err != nil || counted[string(pub)] {
				continue
			}
			sig, err := MatterRaw(CodeEd25519Sig, couple.Sig, ed25519.SignatureSize)
			if err != nil {
				continue
			}
			// Counted by key, not by text, so one witness is one vote however
			// it is written.
			if ed25519.Verify(pub, ev.Raw, sig) {
				counted[string(pub)] = true
			}
		}
	}
	return len(counted), uint64(len(counted)) >= ev.TOAD, nil
}
