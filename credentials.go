package keri

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Credentials: ACDCs, the registries they live in, and the TEL events that say
// whether one is still valid.
//
// The requirement this exists to serve is offline verification. Somebody is
// handed a credential on a phone with no network and has to decide whether it
// is genuine. Everything they need is in the bytes: the credential's identifier
// is a digest of the credential itself, so reproducing that digest — and the
// digests of the sections nested inside it — is the whole check. There is
// nothing to look up and nobody to ask.
//
// That is also why this file is as fussy as it is about serialisation. A
// verifier only ever sees bytes somebody else produced, so "it round-trips
// through my own code" proves nothing. The bytes have to be the ones the
// reference implementation would have written, down to field order.

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

// The two protocols whose events appear in this file.
//
// A credential is ACDC; the registry and the TEL events that govern it are
// KERI, even though they are all part of one credential's story. The version
// string names the protocol, so getting this wrong changes the bytes and
// therefore the identifier.
const ()

// leadingVersion matches an event's own version string, anchored at the start.
//
// Anchored on purpose. `serialize` in interaction.go replaces every match,
// which is safe for a key event whose fields are all identifiers and numbers,
// but a credential carries arbitrary issuer-supplied claims — a claim whose
// value happened to read `KERI10JSON0000ff_` would be silently rewritten, and
// the credential would then fail to verify for reasons nothing in the code
// would explain.
var leadingVersion = regexp.MustCompile(
	`^\{"v":"(?:KERI|ACDC)(?:[0-9a-f]{2}JSON[0-9a-f]{6}_|[A-Za-z0-9_-]{3}JSON[A-Za-z0-9_-]{4}\.)"`)

// serializeVersioned renders an event and fills in the size its leading version
// string declares.
//
// Two passes are unavoidable, for the reason given on `serialize`: the version
// string states the length of the serialised event and is part of it. The
// placeholder is written at the final width, so filling in the real size cannot
// change the length it is declaring.
func serializeVersioned(event interface{}, proto Protocol, v Version) ([]byte, error) {
	raw, err := marshalCanonical(event)
	if err != nil {
		return nil, err
	}
	if !leadingVersion.Match(raw) {
		return nil, fmt.Errorf("the event does not begin with a version string, " +
			"so there is nowhere to declare its size")
	}
	vs, err := VersionString(proto, v, len(raw))
	if err != nil {
		return nil, err
	}
	if len(vs) != versionStringLen(v) {
		return nil, fmt.Errorf("the version string is %d characters and the placeholder "+
			"was %d, so the declared size is now wrong", len(vs), versionStringLen(v))
	}
	out := append([]byte(nil), raw...)
	copy(out[versionFieldOffset:versionFieldOffset+versionStringLen(v)], vs)
	return out, nil
}

// marshalCanonical serialises a value the way KERI does.
//
// Go's json.Marshal escapes `<`, `>` and `&` so that output is safe to embed in
// HTML. The reference implementation does not, and a digest is taken over these
// exact bytes — so a credential holding a claim like "Smith & Sons" would get a
// different identifier here than everywhere else, and would be unverifiable by
// anyone. The escaping has to be off.
func marshalCanonical(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a newline; the canonical form has none.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// ---------------------------------------------------------------------------
// Ordered JSON
// ---------------------------------------------------------------------------

// A credential carries fields nobody here chose: the issuer's claims, an edge
// block, a rules block, a whole JSON schema. Their order is part of what was
// digested, so it has to survive being read and written again unchanged.
//
// Go marshals a map alphabetically, which destroys that order silently — no
// error, just a different identifier. So nothing in this file goes through a
// map[string]interface{}. Values are carried as the bytes they arrived as, and
// objects as an ordered list of members.

// jsonMember is one key and the bytes of its value, exactly as written.
type jsonMember struct {
	Key   string
	Value json.RawMessage
}

// jsonObject is a JSON object that remembers the order it was written in.
type jsonObject []jsonMember

// index returns the position of a key, or -1.
func (o jsonObject) index(key string) int {
	for i := range o {
		if o[i].Key == key {
			return i
		}
	}
	return -1
}

// get returns the raw bytes of a key's value.
func (o jsonObject) get(key string) (json.RawMessage, bool) {
	if i := o.index(key); i >= 0 {
		return o[i].Value, true
	}
	return nil, false
}

// getString returns a key's value when it is a string.
func (o jsonObject) getString(key string) (string, bool) {
	raw, ok := o.get(key)
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// set assigns a key, keeping the position it already had.
//
// This is Python's dict update, which is what the reference implementation uses
// to fold an issuer's claims into an attribute block that already carries `d`,
// `i` and `dt`. Overwriting in place rather than appending is the whole point:
// `dt` is seeded before the claims are merged, so the claims' own `dt` lands in
// the seeded position, not at the end. Appending instead would reorder the
// block and change the credential's identifier.
func (o *jsonObject) set(key string, value json.RawMessage) {
	if i := o.index(key); i >= 0 {
		(*o)[i].Value = value
		return
	}
	*o = append(*o, jsonMember{Key: key, Value: value})
}

// setString assigns a string-valued key.
func (o *jsonObject) setString(key, value string) error {
	raw, err := marshalCanonical(value)
	if err != nil {
		return err
	}
	o.set(key, raw)
	return nil
}

// MarshalJSON writes the object back in its original order.
func (o jsonObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := marshalCanonical(m.Key)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		if len(m.Value) == 0 {
			return nil, fmt.Errorf("the %q field has no value", m.Key)
		}
		buf.Write(m.Value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// parseJSONObject reads a JSON object, keeping its field order.
//
// Values come back as the bytes they were written as, compacted but otherwise
// untouched, so a nested object's own field order survives too. That matters:
// an edge block or a schema's `properties` is digested as written, and this
// package has no business knowing what is inside either.
func parseJSONObject(raw []byte) (jsonObject, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("could not read the object: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object, got %v", tok)
	}
	var out jsonObject
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("could not read a field name: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected a field name, got %v", keyTok)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("could not read the value of %q: %w", key, err)
		}
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, value); err != nil {
			return nil, fmt.Errorf("the value of %q is not valid JSON: %w", key, err)
		}
		if out.index(key) >= 0 {
			// Two fields with one name: which one a reader sees depends on the
			// reader, so the digest is not well defined. Refuse rather than pick.
			return nil, fmt.Errorf("the field %q appears twice, so what was digested is ambiguous", key)
		}
		out = append(out, jsonMember{Key: key, Value: compacted.Bytes()})
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("the object does not end where it should: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Self-addressing identifiers
// ---------------------------------------------------------------------------

// saidDummy is the placeholder written into an identifier field before hashing.
//
// Exactly as wide as the identifier that replaces it, so that substituting the
// real value cannot change the length the version string has already declared.
// `#` because it is not a base64 character, so a placeholder can never be
// mistaken for a real identifier that leaked out unfilled.
func saidDummy() string {
	return strings.Repeat("#", saidPlaceholderLen)
}

// saidOf digests bytes and checks the answer is the width that was reserved.
func saidOf(raw []byte) (string, error) {
	said, err := Blake3SAID(raw)
	if err != nil {
		return "", fmt.Errorf("could not compute the identifier: %w", err)
	}
	if len(said) != saidPlaceholderLen {
		return "", fmt.Errorf("the identifier is %d characters and the placeholder was %d, "+
			"so the declared size is now wrong", len(said), saidPlaceholderLen)
	}
	return said, nil
}

// saidifyObject computes the self-addressing identifier of an ordered object
// and fills it in.
//
// The labels are the fields to blank before hashing. There is usually one, but
// a registry inception has two — its identifier and its prefix are the same
// digest, so both must be blank while it is taken. Blanking only one produces a
// digest of an event that never existed.
//
// The object may or may not carry a version string. A schema does not; a
// registry inception does, and its declared size has to be corrected for the
// blanked form before hashing, which is what `proto` is for.
func saidifyObject(o jsonObject, proto Protocol, v Version, labels ...string) (string, error) {
	dummied := make(jsonObject, len(o))
	copy(dummied, o)
	for _, label := range labels {
		if dummied.index(label) < 0 {
			return "", fmt.Errorf("cannot compute an identifier: there is no %q field to put it in", label)
		}
		if err := dummied.setString(label, saidDummy()); err != nil {
			return "", err
		}
	}
	var raw []byte
	var err error
	if proto == "" {
		raw, err = marshalCanonical(dummied)
	} else {
		raw, err = serializeVersioned(dummied, proto, v)
	}
	if err != nil {
		return "", err
	}
	return saidOf(raw)
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

// SchemaInput is a JSON schema to give a self-addressing identifier to.
type SchemaInput struct {
	// Carried as raw bytes. A schema's field order is part of its identifier,
	// and this package neither chooses that order nor is entitled to change it.
	Schema json.RawMessage `json:"schema"`
}

// BuildSchema fills a schema's $id with the digest of the schema itself.
//
// A credential names its schema by that identifier, so a verifier holding the
// schema can confirm offline that it is the one the credential was issued
// against — and cannot be handed a modified schema that would accept a forgery.
//
// $id rather than d: a schema is a JSON Schema document, not a KERI event, and
// it uses the identifier field its own format defines. Nothing else differs.
// It carries no version string, so there is no size to declare.
func BuildSchema(in SchemaInput) ([]byte, error) {
	if len(in.Schema) == 0 {
		return nil, fmt.Errorf("there is no schema to identify")
	}
	schema, err := parseJSONObject(in.Schema)
	if err != nil {
		return nil, fmt.Errorf("the schema is not a readable JSON object: %w", err)
	}
	said, err := saidifyObject(schema, "", V1, schemaIDLabel)
	if err != nil {
		return nil, err
	}
	if err := schema.setString(schemaIDLabel, said); err != nil {
		return nil, err
	}
	return marshalCanonical(schema)
}

// schemaIDLabel is where a JSON Schema document carries its identifier.
const schemaIDLabel = "$id"

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

// RegistryInput is what founding a credential registry is given.
type RegistryInput struct {
	Issuer  string   `json:"issuer"`
	Toad    int      `json:"toad"`
	Backers []string `json:"backers"`
	// Nonce is what makes two registries with the same issuer different
	// identities. Supplied by the caller rather than generated here, so that
	// founding a registry is reproducible and can be held to a fixed answer.
	Nonce string `json:"nonce"`
}

// vcpWire is a registry inception in the order KERI serialises it.
type vcpWire struct {
	V  string   `json:"v"`
	T  string   `json:"t"`
	D  string   `json:"d"`
	I  string   `json:"i"`
	II string   `json:"ii"`
	S  string   `json:"s"`
	C  []string `json:"c"`
	BT string   `json:"bt"`
	B  []string `json:"b"`
	N  string   `json:"n"`
}

// BuildRegistryInception returns the canonical bytes of a registry inception.
//
// The registry's identifier and its own event identifier are the same digest —
// a registry, like an identity, IS the digest of the event that founded it. So
// both fields are blanked together, hashed once, and filled with the same
// answer. Hashing with only one blanked would digest an event that never
// existed and produce a registry nothing else can name.
func BuildRegistryInception(in RegistryInput) ([]byte, error) {
	if in.Issuer == "" {
		return nil, fmt.Errorf("a registry must name the identity that governs it")
	}
	if in.Nonce == "" {
		return nil, fmt.Errorf("a registry needs a nonce, or two registries founded by " +
			"the same issuer would be the same registry")
	}
	backers := in.Backers
	if backers == nil {
		// nil would serialise as null; the absence of backers is an empty list.
		backers = []string{}
	}
	if len(backers) == 0 && in.Toad != 0 {
		return nil, fmt.Errorf("a registry with no backers cannot require %d of them", in.Toad)
	}
	if len(backers) > 0 && (in.Toad < 1 || in.Toad > len(backers)) {
		return nil, fmt.Errorf("a threshold of %d cannot be met by %d backers", in.Toad, len(backers))
	}

	w := vcpWire{
		V:  placeholderVersionString(ProtocolKERI, V1),
		T:  ilkRegistryInception,
		D:  saidDummy(),
		I:  saidDummy(),
		II: in.Issuer,
		S:  sequenceNumber(0),
		C:  []string{},
		BT: sequenceNumber(in.Toad),
		B:  backers,
		N:  in.Nonce,
	}
	dummy, err := serializeVersioned(w, ProtocolKERI, V1)
	if err != nil {
		return nil, err
	}
	said, err := saidOf(dummy)
	if err != nil {
		return nil, err
	}
	w.D = said
	w.I = said
	return serializeVersioned(w, ProtocolKERI, V1)
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// CredentialInput is what issuing a credential is given.
type CredentialInput struct {
	SchemaSAID string `json:"schema_said"`
	Issuer     string `json:"issuer"`
	// Recipient is who the credential is about. Omitted for a credential that
	// names no holder — a public attestation rather than something issued to
	// somebody.
	Recipient string `json:"recipient"`
	// Registry is the credential's revocation registry. Empty means the
	// credential is not registry-backed and carries no `ri` field at all.
	// Inventing an empty one would change the identifier.
	Registry string `json:"registry"`
	// Data are the issuer's claims, carried as the bytes they arrived as so
	// their order survives. `dt` is required: it moves to a fixed position in
	// the attribute block, and a builder that filled it with the current time
	// would produce a credential the caller cannot predict or reproduce.
	Data json.RawMessage `json:"data"`
	// Source is the edge block: what other credential this one depends on.
	Source json.RawMessage `json:"source"`
	// Rules is the rules block: the terms the credential is issued under.
	Rules json.RawMessage `json:"rules"`
	// Private marks a privacy-preserving credential, which carries a salt at
	// the top level and in its attribute block. The salt is part of both
	// digests, so a holder can disclose one attribute without the verifier
	// being able to guess the rest by hashing candidates.
	Private bool   `json:"private"`
	Salt    string `json:"salt"`
}

// acdcWire is a credential in the order ACDC serialises it.
//
// The optional fields are omitted rather than emitted empty. `ri` absent and
// `ri` present-but-empty are different credentials with different identifiers,
// and only one of them is what the reference implementation writes.
type acdcWire struct {
	V  string          `json:"v"`
	D  string          `json:"d"`
	U  string          `json:"u,omitempty"`
	I  string          `json:"i"`
	RI string          `json:"ri,omitempty"`
	S  string          `json:"s"`
	A  json.RawMessage `json:"a"`
	E  json.RawMessage `json:"e,omitempty"`
	R  json.RawMessage `json:"r,omitempty"`
}

// BuildCredential returns the canonical bytes of an ACDC.
//
// THE ORDER THE DIGESTS ARE TAKEN IN.
//
// A credential's identifier is a digest of the whole credential, and the
// attribute block inside it has an identifier of its own. So the inner one is
// computed FIRST and written in, and only then is the outer one taken over the
// result. Doing it the other way round — or recomputing the inner one after —
// digests a credential whose attribute block does not match its own identifier,
// which every verifier rejects. None of this is visible from the field list,
// which is why it is written down here.
//
// The edge and rules blocks are different: this version of the format embeds
// them as given, with no identifier of their own, so they are digested only as
// part of the credential. They still have to survive byte-for-byte, which is
// why they are carried as raw JSON and never through a map.
func BuildCredential(in CredentialInput) ([]byte, error) {
	if in.Issuer == "" {
		return nil, fmt.Errorf("a credential must name who issued it")
	}
	if in.SchemaSAID == "" {
		return nil, fmt.Errorf("a credential must name the schema it was issued against")
	}
	if in.Private && in.Salt == "" {
		return nil, fmt.Errorf("a privacy-preserving credential needs a salt, and generating " +
			"one here would make the credential unreproducible")
	}

	attributes, err := buildAttributes(in)
	if err != nil {
		return nil, err
	}
	// The inner digest, taken before anything else. See the note above.
	attributeSAID, err := saidifyObject(attributes, "", V1, saidLabel)
	if err != nil {
		return nil, err
	}
	if err := attributes.setString(saidLabel, attributeSAID); err != nil {
		return nil, err
	}
	attributeBytes, err := marshalCanonical(attributes)
	if err != nil {
		return nil, err
	}

	w := acdcWire{
		V: placeholderVersionString(ProtocolACDC, V1),
		D: saidDummy(),
		I: in.Issuer,
		S: in.SchemaSAID,
		A: attributeBytes,
	}
	if in.Private {
		w.U = in.Salt
	}
	if in.Registry != "" {
		w.RI = in.Registry
	}
	if len(in.Source) > 0 {
		if w.E, err = compactRaw(in.Source, "edge block"); err != nil {
			return nil, err
		}
	}
	if len(in.Rules) > 0 {
		if w.R, err = compactRaw(in.Rules, "rules block"); err != nil {
			return nil, err
		}
	}

	// The outer digest, over the credential with the finished attribute block
	// already in place.
	dummy, err := serializeVersioned(w, ProtocolACDC, V1)
	if err != nil {
		return nil, err
	}
	said, err := saidOf(dummy)
	if err != nil {
		return nil, err
	}
	w.D = said
	return serializeVersioned(w, ProtocolACDC, V1)
}

// buildAttributes assembles a credential's attribute block.
//
// The order is fixed and is not the order the claims arrived in: the block's
// own identifier, then the salt if the credential is private, then who it is
// about, then the timestamp, and only then the claims. The claims are then
// folded in on top, which means a claim named `dt` lands in the position
// already reserved for it rather than at the end. That fold is why `set`
// overwrites in place, and it is the single most easily-missed detail in the
// whole format.
func buildAttributes(in CredentialInput) (jsonObject, error) {
	claims, err := parseJSONObject(in.Data)
	if err != nil {
		return nil, fmt.Errorf("the credential's claims are not a readable JSON object: %w", err)
	}
	dt, ok := claims.getString(attributeDateLabel)
	if !ok {
		return nil, fmt.Errorf("a credential's claims must carry a %q timestamp; filling one "+
			"in here would produce a credential the caller cannot reproduce", attributeDateLabel)
	}

	var attributes jsonObject
	if err := attributes.setString(saidLabel, saidDummy()); err != nil {
		return nil, err
	}
	if in.Private {
		if err := attributes.setString(saltLabel, in.Salt); err != nil {
			return nil, err
		}
	}
	if in.Recipient != "" {
		if err := attributes.setString(subjectLabel, in.Recipient); err != nil {
			return nil, err
		}
	}
	if err := attributes.setString(attributeDateLabel, dt); err != nil {
		return nil, err
	}
	for _, claim := range claims {
		attributes.set(claim.Key, claim.Value)
	}
	return attributes, nil
}

// compactRaw checks a block is valid JSON and strips insignificant whitespace.
//
// Compacted rather than re-marshalled: compaction leaves the bytes of every
// value and the order of every field exactly as they were, which re-marshalling
// through any Go value would not.
func compactRaw(raw json.RawMessage, what string) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, fmt.Errorf("the %s is not valid JSON: %w", what, err)
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// The transaction event log: issuance and revocation
// ---------------------------------------------------------------------------

// Field labels, named rather than spelled inline so that a typo is a compile
// error somewhere rather than a wrong digest everywhere.
//
// `i` has two names because it means two different things depending on where it
// appears: at the top of an event it is that event's own prefix, and inside a
// credential's attribute block it is who the credential is ABOUT. Reading one
// as the other would have a verifier report the holder as the issuer, so the
// two uses are kept visibly distinct even though the bytes are the same.
const (
	saidLabel          = "d"
	prefixLabel        = "i"
	saltLabel          = "u"
	subjectLabel       = "i"
	attributeDateLabel = "dt"
)

// The transaction event types.
const (
	ilkRegistryInception = "vcp"
	ilkIssuance          = "iss"
	ilkRevocation        = "rev"
)

// IssuanceInput is what placing a credential into a registry is given.
type IssuanceInput struct {
	CredentialSAID string `json:"credential_said"`
	Registry       string `json:"registry"`
	DT             string `json:"dt"`
}

// RevocationInput is what withdrawing a credential is given.
type RevocationInput struct {
	CredentialSAID string `json:"credential_said"`
	Registry       string `json:"registry"`
	// PriorISSSAID chains the revocation to the issuance it withdraws. Without
	// it a revocation is unattached to anything, and a holder could present the
	// issuance while claiming the revocation belongs to some other credential.
	PriorISSSAID string `json:"prior_iss_said"`
	DT           string `json:"dt"`
}

// telWire is an issuance or a revocation in the order KERI serialises them.
//
// One struct for both: the two events have the same fields in the same order,
// and a revocation adds `p` between the registry and the timestamp. Kept
// together so the shared order cannot drift apart between them.
type telWire struct {
	V  string `json:"v"`
	T  string `json:"t"`
	D  string `json:"d"`
	I  string `json:"i"`
	S  string `json:"s"`
	RI string `json:"ri"`
	P  string `json:"p,omitempty"`
	DT string `json:"dt"`
}

// BuildIssuance returns the canonical bytes of a credential issuance.
//
// The event's `i` is the CREDENTIAL's identifier, not the issuer's and not the
// registry's: a credential has its own transaction log, and this is the first
// event in it. The registry is named separately in `ri`. Confusing the two
// produces a log no peer can reconcile with its own.
func BuildIssuance(in IssuanceInput) ([]byte, error) {
	if in.CredentialSAID == "" {
		return nil, fmt.Errorf("an issuance must name the credential it issues")
	}
	if in.Registry == "" {
		return nil, fmt.Errorf("an issuance must name the registry it issues into")
	}
	if in.DT == "" {
		return nil, fmt.Errorf("an issuance must say when it happened")
	}
	w := telWire{
		V:  placeholderVersionString(ProtocolKERI, V1),
		T:  ilkIssuance,
		D:  saidDummy(),
		I:  in.CredentialSAID,
		S:  sequenceNumber(0),
		RI: in.Registry,
		DT: in.DT,
	}
	return saidifyTEL(w)
}

// BuildRevocation returns the canonical bytes of a credential revocation.
//
// Sequence number 1, chained by digest to the issuance at 0. Both are what
// makes an offline decision possible: a verifier holding the issuance and the
// revocation can tell they belong to the same credential and which came second,
// without asking anybody.
func BuildRevocation(in RevocationInput) ([]byte, error) {
	if in.CredentialSAID == "" {
		return nil, fmt.Errorf("a revocation must name the credential it withdraws")
	}
	if in.Registry == "" {
		return nil, fmt.Errorf("a revocation must name the registry the credential is in")
	}
	if in.PriorISSSAID == "" {
		return nil, fmt.Errorf("a revocation must chain to the issuance it withdraws")
	}
	if in.DT == "" {
		return nil, fmt.Errorf("a revocation must say when it happened")
	}
	w := telWire{
		V:  placeholderVersionString(ProtocolKERI, V1),
		T:  ilkRevocation,
		D:  saidDummy(),
		I:  in.CredentialSAID,
		S:  sequenceNumber(1),
		RI: in.Registry,
		P:  in.PriorISSSAID,
		DT: in.DT,
	}
	return saidifyTEL(w)
}

// saidifyTEL takes the digest of a transaction event and fills it in.
func saidifyTEL(w telWire) ([]byte, error) {
	dummy, err := serializeVersioned(w, ProtocolKERI, V1)
	if err != nil {
		return nil, err
	}
	said, err := saidOf(dummy)
	if err != nil {
		return nil, err
	}
	w.D = said
	return serializeVersioned(w, ProtocolKERI, V1)
}

// ---------------------------------------------------------------------------
// Verification — the point of all of the above
// ---------------------------------------------------------------------------

// Everything below works from bytes somebody else produced. That is the case
// that matters: a verifier which can only check credentials it issued itself is
// no use to anyone, and is exactly what an implementation that quietly
// serialises differently from the reference still passes its own tests as.

// Credential is what a verifier learns from a credential's bytes.
//
// Every field here was read out of the credential and confirmed against its
// digests. Nothing was looked up.
type Credential struct {
	SAID          string
	Issuer        string
	SchemaSAID    string
	Registry      string
	Recipient     string
	Salt          string
	AttributeSAID string
	Attributes    json.RawMessage
	Edges         json.RawMessage
	Rules         json.RawMessage
	Raw           []byte
}

// Private reports whether the credential is privacy-preserving.
func (c *Credential) Private() bool { return c.Salt != "" }

// VerifyCredential checks a credential against itself, using nothing else.
//
// This is the offline check. It confirms, in this order:
//
//  1. the bytes are the canonical serialisation — not merely valid JSON that
//     happens to parse to the same thing;
//  2. the version string declares the length the credential actually is;
//  3. the attribute block's identifier is a digest of that block;
//  4. the credential's identifier is a digest of the whole credential.
//
// The inner check comes first for the same reason the inner digest is computed
// first when building: the outer digest covers the inner identifier, so an
// outer digest that matched while the inner one did not would mean somebody had
// substituted an attribute block and recomputed around it. Checking the outer
// one alone would not catch a forged attribute block whose own `d` was left
// stale, and checking them in the other order reports the wrong failure.
//
// What this does NOT establish: that the issuer authorised it. That is a
// signature over these bytes and a walk of the issuer's key history, which is a
// separate concern from the credential's own integrity. This function proves
// the bytes are intact and self-consistent; it never claims they are genuine.
func VerifyCredential(raw []byte) (*Credential, error) {
	sad, err := parseCanonical(raw)
	if err != nil {
		return nil, err
	}
	ver, err := checkCredentialVersion(raw, ProtocolACDC)
	if err != nil {
		return nil, err
	}

	attributesRaw, ok := sad.get("a")
	if !ok {
		return nil, fmt.Errorf("the credential has no attribute block")
	}
	attributes, err := parseCanonical(attributesRaw)
	if err != nil {
		return nil, fmt.Errorf("the attribute block is not canonical: %w", err)
	}
	attributeSAID, err := checkCredentialSAID(attributes, "", ver, saidLabel)
	if err != nil {
		return nil, fmt.Errorf("the attribute block does not match its own identifier: %w", err)
	}

	said, err := checkCredentialSAID(sad, ProtocolACDC, ver, saidLabel)
	if err != nil {
		return nil, fmt.Errorf("the credential does not match its own identifier: %w", err)
	}

	out := &Credential{
		SAID:          said,
		AttributeSAID: attributeSAID,
		Attributes:    attributesRaw,
		Raw:           append([]byte(nil), raw...),
	}
	out.Issuer, _ = sad.getString("i")
	out.SchemaSAID, _ = sad.getString("s")
	out.Registry, _ = sad.getString("ri")
	out.Salt, _ = sad.getString(saltLabel)
	out.Recipient, _ = attributes.getString(subjectLabel)
	out.Edges, _ = sad.get("e")
	out.Rules, _ = sad.get("r")

	if out.Issuer == "" {
		return nil, fmt.Errorf("the credential names no issuer")
	}
	if out.SchemaSAID == "" {
		return nil, fmt.Errorf("the credential names no schema")
	}
	return out, nil
}

// VerifySchema checks a schema against its own $id and returns it.
//
// A verifier that accepted a schema without checking this could be handed a
// widened schema that validates a forgery, while the credential still named the
// original.
func VerifySchema(raw []byte) (string, error) {
	sad, err := parseCanonical(raw)
	if err != nil {
		return "", err
	}
	said, err := checkCredentialSAID(sad, "", V1, schemaIDLabel)
	if err != nil {
		return "", fmt.Errorf("the schema does not match its own identifier: %w", err)
	}
	return said, nil
}

// TELEvent is a transaction event read back from its bytes.
type TELEvent struct {
	Ilk string
	// SAID is the event's own identifier.
	SAID string
	// Subject is what the event is about: for a registry inception the registry
	// itself, for an issuance or a revocation the credential.
	Subject  string
	SN       int
	Registry string
	Prior    string
	DateTime string
	Raw      []byte
}

// VerifyTELEvent checks a registry, issuance or revocation event against itself.
//
// A registry inception is digested with BOTH its identifier and its prefix
// blank, because they are the same digest; the others have one identifier. That
// difference is not visible in the serialised event and is the thing most
// easily got wrong here, so the labels are chosen from the event type rather
// than assumed.
func VerifyTELEvent(raw []byte) (*TELEvent, error) {
	sad, err := parseCanonical(raw)
	if err != nil {
		return nil, err
	}
	ver, err := checkCredentialVersion(raw, ProtocolKERI)
	if err != nil {
		return nil, err
	}
	ilk, ok := sad.getString("t")
	if !ok {
		return nil, fmt.Errorf("the event does not say what type it is")
	}

	var labels []string
	switch ilk {
	case ilkRegistryInception:
		labels = []string{saidLabel, prefixLabel}
	case ilkIssuance, ilkRevocation:
		labels = []string{saidLabel}
	default:
		return nil, fmt.Errorf("%q is not a transaction event this understands", ilk)
	}

	said, err := checkCredentialSAID(sad, ProtocolKERI, ver, labels...)
	if err != nil {
		return nil, fmt.Errorf("the %s event does not match its own identifier: %w", ilk, err)
	}

	out := &TELEvent{Ilk: ilk, SAID: said, Raw: append([]byte(nil), raw...)}
	out.Subject, _ = sad.getString("i")
	out.Registry, _ = sad.getString("ri")
	out.Prior, _ = sad.getString("p")
	out.DateTime, _ = sad.getString("dt")
	snText, ok := sad.getString("s")
	if !ok {
		return nil, fmt.Errorf("the %s event carries no sequence number", ilk)
	}
	if out.SN, err = parseSequenceNumber(snText); err != nil {
		return nil, err
	}
	if ilk == ilkRegistryInception && out.Subject != said {
		return nil, fmt.Errorf("a registry's prefix must be its own identifier, but this one is %q", out.Subject)
	}
	return out, nil
}

// The states a credential's transaction log can leave it in.
const (
	StatusIssued  = "issued"
	StatusRevoked = "revoked"
)

// CredentialStatus decides, offline, whether a credential is still valid.
//
// Given the credential's identifier and the transaction events somebody handed
// over, in order, it walks the log and returns what state it ends in. The point
// is that "I was given an issuance" is not an answer: a holder presenting a
// revoked credential can simply not hand over the revocation, so the decision
// has to rest on a chain that is verifiably complete — sequence numbers with no
// gaps, and each event naming the digest of the one before it.
//
// What this cannot know is whether there are later events it was not given.
// Nothing offline can. What it CAN do is refuse a log with a hole in it, which
// is what a withheld revocation would have to look like if the holder also
// wanted to present anything issued after it.
func CredentialStatus(credentialSAID string, events [][]byte) (string, error) {
	if credentialSAID == "" {
		return "", fmt.Errorf("no credential was named")
	}
	if len(events) == 0 {
		return "", fmt.Errorf("no transaction events were given, so nothing is known about %s", credentialSAID)
	}

	status := ""
	prior := ""
	for i, raw := range events {
		ev, err := VerifyTELEvent(raw)
		if err != nil {
			return "", fmt.Errorf("event %d of the log: %w", i, err)
		}
		if ev.Subject != credentialSAID {
			return "", fmt.Errorf("event %d of the log is about %s, not %s", i, ev.Subject, credentialSAID)
		}
		if ev.SN != i {
			return "", fmt.Errorf("event %d of the log is numbered %d, so the log has a gap "+
				"and something may be missing from it", i, ev.SN)
		}
		if i == 0 {
			if ev.Ilk != ilkIssuance {
				return "", fmt.Errorf("a credential's log must open with an issuance, not a %s", ev.Ilk)
			}
			status = StatusIssued
		} else {
			if ev.Prior != prior {
				return "", fmt.Errorf("event %d chains to %s but the event before it is %s, "+
					"so these are not one log", i, ev.Prior, prior)
			}
			switch ev.Ilk {
			case ilkRevocation:
				status = StatusRevoked
			default:
				return "", fmt.Errorf("%q cannot follow an issuance in a credential's log", ev.Ilk)
			}
		}
		prior = ev.SAID
	}
	return status, nil
}

// parseCanonical reads a value and insists it was written canonically.
//
// Re-serialising the parsed form and requiring it to equal the input is the
// check. Two byte strings that parse to the same JSON are still two different
// digests, so a verifier that quietly accepted a prettified or re-spaced
// credential would compute an identifier nobody else does — and would then
// report a valid credential as forged. Better to say which of the two things
// went wrong.
func parseCanonical(raw []byte) (jsonObject, error) {
	sad, err := parseJSONObject(raw)
	if err != nil {
		return nil, fmt.Errorf("the bytes are not a readable JSON object: %w", err)
	}
	again, err := marshalCanonical(sad)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, fmt.Errorf("the bytes are not the canonical serialisation, so no digest " +
			"taken over them would match")
	}
	return sad, nil
}

// checkCredentialVersion confirms the version string declares the length the bytes are.
//
// This is what makes a serialised event self-delimiting inside a stream. An
// event whose declared size is wrong cuts the next one in half, so it is worth
// catching here rather than three events later.
func checkCredentialVersion(raw []byte, proto Protocol) (Version, error) {
	if !leadingVersion.Match(raw) {
		return Version{}, fmt.Errorf("the bytes do not begin with a version string, so they " +
			"are not canonical serialisation")
	}
	// Read the version out of the bytes rather than assuming one. This is the
	// point at which a credential from a stranger declares which CESR version
	// it is written in, and the reason no negotiation is needed to read it.
	gotProto, ver, declared, err := ParseVersionString(
		string(raw[versionFieldOffset : versionFieldOffset+versionStringLenOf(raw)]))
	if err != nil {
		return Version{}, err
	}
	if gotProto != proto {
		return Version{}, fmt.Errorf("these are %s bytes but %s was expected", gotProto, proto)
	}
	if declared != len(raw) {
		return Version{}, fmt.Errorf("the version string declares %d bytes but there are %d",
			declared, len(raw))
	}
	return ver, nil
}

// versionStringLenOf reports how wide the version string in these bytes is,
// which is how the two encodings are told apart before either is parsed.
func versionStringLenOf(raw []byte) int {
	// The 1.0 form ends in `_` at 17 characters; the 2.0 form ends in `.` at 16.
	if len(raw) >= versionFieldOffset+16 && raw[versionFieldOffset+15] == '.' {
		return 16
	}
	return 17
}

// checkCredentialSAID recomputes an identifier and compares it with the one written.
func checkCredentialSAID(sad jsonObject, proto Protocol, v Version, labels ...string) (string, error) {
	if len(labels) == 0 {
		return "", fmt.Errorf("no identifier field was named, so nothing would be checked")
	}
	said, ok := sad.getString(labels[0])
	if !ok {
		return "", fmt.Errorf("there is no %q field to check", labels[0])
	}
	if len(said) != saidPlaceholderLen {
		return "", fmt.Errorf("%q is not a %d-character identifier", said, saidPlaceholderLen)
	}
	computed, err := saidifyObject(sad, proto, v, labels...)
	if err != nil {
		return "", err
	}
	if computed != said {
		return "", fmt.Errorf("it says %s but its contents digest to %s", said, computed)
	}
	// Where more than one field carries the identifier, they must agree; the
	// digest was taken with all of them blank, so a mismatch means one was
	// tampered with after the fact.
	for _, label := range labels[1:] {
		other, ok := sad.getString(label)
		if !ok {
			return "", fmt.Errorf("there is no %q field to check", label)
		}
		if other != said {
			return "", fmt.Errorf("the %q field is %s but the %q field is %s, and both are "+
				"the same digest", labels[0], said, label, other)
		}
	}
	return said, nil
}

// parseSequenceNumber reads a sequence number the way KERI writes one.
//
// Lowercase hexadecimal, no padding, no prefix. Strict rather than forgiving:
// "1" and "01" would be the same number but are different bytes and therefore
// different events, so accepting both would mean accepting an event whose
// digest cannot be reproduced.
func parseSequenceNumber(text string) (int, error) {
	if text == "" {
		return 0, fmt.Errorf("the event carries no sequence number")
	}
	var sn int
	if _, err := fmt.Sscanf(text, "%x", &sn); err != nil {
		return 0, fmt.Errorf("%q is not a hexadecimal sequence number: %w", text, err)
	}
	if sn < 0 {
		return 0, fmt.Errorf("%q is not a position in a log", text)
	}
	if sequenceNumber(sn) != text {
		return 0, fmt.Errorf("%q is not how KERI writes the number %d", text, sn)
	}
	return sn, nil
}

// ---------------------------------------------------------------------------
// The conformance seam
// ---------------------------------------------------------------------------

// AnswerCredential produces this implementation's answer to a credential case.
//
// The case kind says "credential" for everything in this file — a schema, a
// registry, an ACDC, an issuance, a revocation — so the input decides which.
// Dispatched on which fields the input HAS, never on the case's id: an
// implementation that recognised the case would pass the suite while being
// unable to do the same thing for anything else, which is the one failure this
// whole package exists to avoid.
func AnswerCredential(c Case) ([]byte, error) {
	var probe struct {
		Schema         json.RawMessage `json:"schema"`
		SchemaSAID     string          `json:"schema_said"`
		Nonce          string          `json:"nonce"`
		CredentialSAID string          `json:"credential_said"`
		PriorISSSAID   string          `json:"prior_iss_said"`
		DT             string          `json:"dt"`
	}
	if err := json.Unmarshal(c.Input, &probe); err != nil {
		return nil, fmt.Errorf("case input is not a credential case: %w", err)
	}

	switch {
	case len(probe.Schema) > 0:
		var in SchemaInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not a schema: %w", err)
		}
		return BuildSchema(in)

	case probe.SchemaSAID != "":
		var in CredentialInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not a credential: %w", err)
		}
		return BuildCredential(in)

	case probe.Nonce != "":
		var in RegistryInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not a registry inception: %w", err)
		}
		return BuildRegistryInception(in)

	case probe.PriorISSSAID != "":
		var in RevocationInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not a revocation: %w", err)
		}
		return BuildRevocation(in)

	case probe.CredentialSAID != "" && probe.DT != "":
		var in IssuanceInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not an issuance: %w", err)
		}
		return BuildIssuance(in)

	case probe.CredentialSAID != "":
		// A credential's TEL state before and after revocation. This case
		// states no serialisation to produce — its expectation is a pair of
		// state markers — so it is asserted by its own test, the way the
		// property and rejection cases are, rather than by returning bytes.
		// See TestCredentialTELState.
		return nil, ErrNotImplemented

	default:
		return nil, fmt.Errorf("this credential case names nothing this knows how to build")
	}
}
