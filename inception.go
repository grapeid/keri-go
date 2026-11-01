package keri

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// An inception event: the event that founds an identity.
//
// This is the one event whose bytes decide who the identity IS. Every later
// event chains back to it by digest, so a byte that differs here does not
// produce a slightly different event — it produces a different person, with a
// key history nobody else will accept.
//
// The shape follows interaction.go: a struct in protocol order, a version
// string that declares its own length, and a digest taken over the event with
// the identifier blanked at exactly the final width.

// icpWire is an inception event in the order KERI serialises it.
//
// Field ORDER is protocol, not style. The version string states the length of
// what follows and the identifier is a digest of the whole thing, so any
// reordering is a different identity. A struct is used because Go marshals a
// struct in declaration order and a map alphabetically — and alphabetical order
// would put "a" first and "v" last, which no KERI implementation can read.
type icpWire struct {
	V string `json:"v"`
	T string `json:"t"`
	D string `json:"d"`
	I string `json:"i"`
	S string `json:"s"`
	// Thresholds are carried as raw bytes because KERI writes them in two
	// shapes: a hex string ("2") or a list of weight strings
	// (["1/2","1/2","1/2"]). Both are normalised before they get here; carrying
	// them as bytes keeps the two shapes from being flattened into one Go type
	// that could only express one of them.
	KT json.RawMessage `json:"kt"`
	K  []string        `json:"k"`
	NT json.RawMessage `json:"nt"`
	N  []string        `json:"n"`
	BT string          `json:"bt"`
	B  []string        `json:"b"`
	C  []string        `json:"c"`
	// Seals are carried as the bytes they arrived as, never through a map: a
	// seal's field order is part of the event, and a Go map would sort it
	// alphabetically and change the identifier.
	A []json.RawMessage `json:"a"`
	// ver is the CESR version this event is being built under. Unexported, so
	// it is never serialised; it exists so the placeholder written on the first
	// pass is the same WIDTH as the version string written on the second. The
	// two encodings differ in width (17 characters against 16), and a
	// placeholder of the wrong width makes the declared size wrong by exactly
	// that difference.
	ver Version
}

// MarshalJSON writes the version placeholder at its final width, so that the
// two serialisation passes agree on length.
func (w icpWire) MarshalJSON() ([]byte, error) {
	type wire icpWire // avoid recursing into this method
	if w.V == "" {
		w.V = placeholderVersionString(ProtocolKERI, w.versionOrDefault())
	}
	return json.Marshal(wire(w))
}

// BuildInception returns the canonical bytes of an inception event.
//
// Two derivation styles live here, and getting the choice wrong is the failure
// this function exists to avoid:
//
//   - BASIC — a single-key inception. The identifier IS the public key (D…), so
//     the identity can be verified by anyone holding only the identifier. The
//     event still carries a SAID in "d", but it is not the identifier.
//   - SELF-ADDRESSING — anything else. The identifier is a digest of the event
//     itself (E…) and equals the SAID, because no single key could stand for a
//     set of keys.
//
// The choice is made from the key count rather than from any label on the
// input, because that is what the reference implementation does: keripy's
// incept() takes an optional derivation code and, when none is given, uses
// basic derivation if and only if there is exactly one key. An implementation
// that always digests breaks every single-key identity that already exists; one
// that always uses the key cannot make a multi-key identity at all.
func BuildInception(in InceptionInput) ([]byte, error) {
	ver, err := resolveVersion(in.Version)
	if err != nil {
		return nil, err
	}
	if len(in.Keys) == 0 {
		return nil, fmt.Errorf("an identity must be founded on at least one key")
	}
	if err := noDuplicates(in.Keys, "signing key"); err != nil {
		return nil, err
	}
	if err := noDuplicateWitnesses(in.Witnesses, "witness"); err != nil {
		return nil, err
	}

	kt, err := renderThreshold(in.Isith, len(in.Keys), 1, "kt")
	if err != nil {
		return nil, err
	}
	nt, err := renderThreshold(in.Nsith, len(in.NextDigests), 0, "nt")
	if err != nil {
		return nil, err
	}
	// Absent means the reference's derived default, not zero. Defaulting to
	// zero would produce an identity whose witnesses need not agree on
	// anything — valid-looking, and unprotected.
	toad, err := inceptionToad(in.Toad, len(in.Witnesses))
	if err != nil {
		return nil, err
	}

	w := icpWire{
		ver: ver,
		T:   "icp",
		S:   sequenceNumber(0), // an inception is always the first event
		KT:  kt,
		K:   in.Keys,
		NT:  nt,
		N:   emptyIfNil(in.NextDigests),
		BT:  hexCount(toad),
		B:   emptyIfNil(in.Witnesses),
		// Configuration traits. Nothing this package builds sets any, but the
		// field is not optional: an event missing "c" is a different length and
		// therefore a different identity.
		C: []string{},
		A: emptySealsIfNil(in.Data),
	}

	// Which derivation applies. The reference infers it from the key count
	// unless told otherwise, and being told otherwise is a real requirement:
	// a single-key identity may legitimately be self-addressing.
	selfAddressing := len(in.Keys) != 1
	switch in.Derivation {
	case "":
	case "self-addressing":
		selfAddressing = true
	case "basic":
		if len(in.Keys) != 1 {
			return nil, fmt.Errorf("basic derivation names the key as the identifier, so "+
				"it needs exactly one key; %d were given", len(in.Keys))
		}
		selfAddressing = false
	default:
		return nil, fmt.Errorf("%q is not a derivation this package knows; use "+
			"\"basic\", \"self-addressing\", or leave it empty for the default",
			in.Derivation)
	}

	blank := strings.Repeat("#", saidPlaceholderLen)
	if !selfAddressing {
		// Basic derivation. The identifier is the key, and it is written in
		// BEFORE the digest is taken — so the SAID covers the real identifier,
		// not a blank, and "d" therefore differs from "i" on these events.
		w.I = in.Keys[0]
		w.D = blank
		dummy, err := serialize(w, ProtocolKERI, ver)
		if err != nil {
			return nil, err
		}
		said, err := Blake3SAID(dummy)
		if err != nil {
			return nil, fmt.Errorf("could not compute the event's identifier: %w", err)
		}
		if len(said) != saidPlaceholderLen {
			return nil, fmt.Errorf("identifier is %d characters and the placeholder was %d, "+
				"so the event's declared size is now wrong", len(said), saidPlaceholderLen)
		}
		w.D = said
	} else {
		// Self-addressing derivation. The digest is taken over the event with
		// BOTH "i" and "d" blanked — neither can be an input to the digest that
		// produces it — and the one digest then fills both fields. That is why
		// "d" and "i" are equal on a multi-key event.
		//
		// This is not the same as blanking "d" alone and hashing again once "i"
		// is known: that second digest is taken over different bytes and comes
		// out different, which would leave an event whose identifier is not its
		// SAID and which every peer would reject.
		w.I, w.D = blank, blank
		raw, err := serialize(w, ProtocolKERI, ver)
		if err != nil {
			return nil, err
		}
		prefix, err := Blake3SAID(raw)
		if err != nil {
			return nil, fmt.Errorf("could not derive the identifier: %w", err)
		}
		if len(prefix) != saidPlaceholderLen {
			return nil, fmt.Errorf("identifier is %d characters and the placeholder was %d, "+
				"so the event's declared size is now wrong", len(prefix), saidPlaceholderLen)
		}
		w.I, w.D = prefix, prefix
	}
	return serialize(w, ProtocolKERI, ver)
}

// hexCount renders a count the way KERI writes every number in an event body:
// lowercase hexadecimal, unpadded, with no prefix.
//
// Stated rather than assumed because 1, "1" and "01" are three different events
// with three different identifiers. This is the same rendering
// sequenceNumber() applies to "s"; it is spelled separately because a threshold
// and a witness count are not sequence numbers and a shared name that said so
// would be a lie the next reader has to check.
func hexCount(n int) string {
	return strconv.FormatInt(int64(n), 16)
}

// renderThreshold normalises a signing threshold into the bytes KERI writes.
//
// Two shapes are legitimate and mean different things:
//
//   - a hex STRING ("2") — any 2 of the keys must sign;
//   - a LIST of weight strings (["1/2","1/2","1/2"]) — the signers' weights must
//     sum to at least 1, which lets some keys count for more than others.
//
// A threshold is never written as a JSON number. A number is accepted on input
// because the reference implementation accepts one, but it is rendered as a hex
// string, because "2" and 2 are different bytes and therefore different
// identities.
//
// floor is the smallest threshold this field may hold, and also the floor on
// the default: the reference defaults to ceil(count/2) but never lets a SIGNING
// threshold fall below 1, because an identity that needs no signatures is not an
// identity. A next-key threshold over an empty list is legitimately 0.
func renderThreshold(raw json.RawMessage, count, floor int, field string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		n := (count + 1) / 2 // ceil(count/2)
		if n < floor {
			n = floor
		}
		return json.Marshal(hexCount(n))
	}

	switch trimmed[0] {
	case '[':
		return renderWeightedThreshold(trimmed, count, field)
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s is not readable: %w", field, err)
		}
		n, err := strconv.ParseInt(s, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("%s is %q, which is neither a hex threshold nor a "+
				"list of weights", field, s)
		}
		if err := checkThresholdFits(int(n), count, floor, field); err != nil {
			return nil, err
		}
		// Re-rendered rather than passed through: the reference normalises, so
		// "02" and "2" must both come out as "2" or the same threshold would
		// produce two identities.
		return json.Marshal(hexCount(int(n)))
	default:
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("%s is not a threshold: %w", field, err)
		}
		if err := checkThresholdFits(int(n), count, floor, field); err != nil {
			return nil, err
		}
		return json.Marshal(hexCount(int(n)))
	}
}

// renderWeightedThreshold validates and re-emits a threshold written as
// weights, through the one threshold reader and renderer (threshold.go).
//
// Re-emitted rather than passed through because the incoming bytes may carry
// whitespace or unreduced fractions, and either changes the event's length and
// therefore its identifier. Order is preserved throughout, because weight n
// belongs to key n.
func renderWeightedThreshold(trimmed string, count int, field string) (json.RawMessage, error) {
	t, err := weightedThreshold(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if t.size > count {
		return nil, fmt.Errorf("%s carries %d weights but there are only %d keys to "+
			"weigh, so the threshold could never be met", field, t.size, count)
	}
	return t.value, nil
}

func checkThresholdFits(n, count, floor int, field string) error {
	if n < floor {
		return fmt.Errorf("%s is %d, and this threshold cannot be lower than %d",
			field, n, floor)
	}
	if n > count {
		return fmt.Errorf("%s requires %d signatures but only %d keys are listed, so the "+
			"threshold could never be met", field, n, count)
	}
	return nil
}

// checkToad refuses a threshold of accountable duplicity the witness list
// cannot satisfy.
//
// Rendered into "bt" and part of the identifier, so a toad larger than the
// witness set is not merely unwise: it founds an identity whose events can
// never become accepted, and it does so silently.
func checkToad(toad, witnesses int) error {
	if witnesses == 0 {
		if toad != 0 {
			return fmt.Errorf("toad is %d but no witnesses are named, so nothing could "+
				"ever receipt this identity's events", toad)
		}
		return nil
	}
	if toad < 1 || toad > witnesses {
		return fmt.Errorf("toad is %d, which is outside the 1..%d a %d-witness set can "+
			"satisfy", toad, witnesses, witnesses)
	}
	return nil
}

// noDuplicates refuses a repeated entry.
//
// A key listed twice would let one signature count as two against the
// threshold, which quietly halves the protection the threshold was chosen for.
// The same holds for a witness against the toad.
func noDuplicates(values []string, what string) error {
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if seen[v] {
			return fmt.Errorf("the same %s is listed twice (%s), which would let one "+
				"signature count as two", what, v)
		}
		seen[v] = true
	}
	return nil
}

// noDuplicateWitnesses refuses a list of witnesses (or registry backers, which
// are witnesses to a registry) with an entry that is not a canonical
// non-transferable identifier, or with one named twice. what names the role in
// the error.
//
// Compared by key rather than by text. Each key has one canonical spelling, so
// requiring that spelling already makes the two agree; comparing keys says so
// outright, and does not depend on it.
func noDuplicateWitnesses(ids []string, what string) error {
	seen := make(map[string]string, len(ids))
	for _, w := range ids {
		key, err := witnessKey(w)
		if err != nil {
			return fmt.Errorf("the %s %q is not a readable non-transferable "+
				"identifier: %w", what, w, err)
		}
		if first, dup := seen[key]; dup {
			return fmt.Errorf("the same %s is listed twice (%s and %s), which would "+
				"let one signature count as two", what, first, w)
		}
		seen[key] = w
	}
	return nil
}

// emptyIfNil keeps an absent list serialising as [] rather than null.
//
// Not cosmetic: "n":[] and "n":null are different bytes, so an event that emits
// null has a different length and a different identifier from the one every
// other implementation produces.
func emptyIfNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func emptySealsIfNil(v []json.RawMessage) []json.RawMessage {
	if v == nil {
		return []json.RawMessage{}
	}
	return v
}

// versionOrDefault is the version this event is built under, falling back to
// the package default when the caller did not set one.
func (w icpWire) versionOrDefault() Version {
	if w.ver == (Version{}) {
		return DefaultVersion
	}
	return w.ver
}
