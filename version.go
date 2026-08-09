package keri

import (
	"fmt"
	"regexp"
	"strings"
)

// Everything that differs between CESR 1.0 and CESR 2.0 lives in this file.
//
// The rest of the package asks for a Version and is otherwise unaware which one
// it is building. That is deliberate and it is the correction five independent
// reviewers converged on: a single constant is one place to change, whereas a
// parameter threaded through every path is the commitment that nothing in the
// package silently assumes 1.0.
//
// The two encodings:
//
//	1.0   {"v":"KERI10JSON00012b_", ...}    17 characters
//	2.0   {"v":"KERICAAJSONAAEq.", ...}     16 characters
//
// Both state the event's total serialised length, which is why the length is
// part of the thing whose length it states — see serialize.

// Protocol is which specification an event belongs to. KERI events are key
// events; ACDC events are credentials. They are versioned independently, so the
// protocol travels with the version everywhere.
type Protocol string

const (
	ProtocolKERI Protocol = "KERI"
	ProtocolACDC Protocol = "ACDC"
)

// Version is a CESR protocol version.
type Version struct {
	Major int
	Minor int
}

var (
	// V1 is CESR 1.0 — what every released implementation speaks today.
	V1 = Version{Major: 1, Minor: 0}
	// V2 is CESR 2.0. Its wire format is NOT FROZEN — see the warning below.
	V2 = Version{Major: 2, Minor: 0}
)

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// Supported reports whether this package can build and read a version.
func (v Version) Supported() bool { return v == V1 || v == V2 }

// b64 is the CESR alphabet. It is URL-safe base64 and the order matters: these
// are the digits sizes are written in under 2.0.
const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func b64Encode(n, width int) (string, error) {
	if n < 0 {
		return "", fmt.Errorf("a size cannot be negative, got %d", n)
	}
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		out[i] = b64[n&0x3f]
		n >>= 6
	}
	if n != 0 {
		return "", fmt.Errorf("the size needs more than %d characters to write", width)
	}
	return string(out), nil
}

func b64Decode(s string) (int, error) {
	n := 0
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(b64, s[i])
		if v < 0 {
			return 0, fmt.Errorf("%q is not a CESR digit", s[i:i+1])
		}
		n = n<<6 | v
	}
	return n, nil
}

// versionStringLen is how wide a version string is, which differs by version.
//
// It matters beyond cosmetics: an event is serialised twice, and the first pass
// writes a placeholder that must be exactly as wide as the final value, or
// filling in the real size changes the length that size is declaring.
func versionStringLen(v Version) int {
	if v == V2 {
		return 16 // KERI + CAA + JSON + AAEq + .
	}
	return 17 // KERI + 10 + JSON + 00012b + _
}

// VersionString renders the first field of an event.
func VersionString(proto Protocol, v Version, size int) (string, error) {
	switch v {
	case V1:
		// Major and minor are single hex digits; the size is six hex digits.
		return fmt.Sprintf("%s%x%xJSON%06x_", proto, v.Major, v.Minor, size), nil
	case V2:
		// The version is three CESR digits — one for major, two for minor —
		// and the size is four.
		major, err := b64Encode(v.Major, 1)
		if err != nil {
			return "", err
		}
		minor, err := b64Encode(v.Minor, 2)
		if err != nil {
			return "", err
		}
		sz, err := b64Encode(size, 4)
		if err != nil {
			return "", fmt.Errorf("event of %d bytes is too large to declare under CESR 2.0: %w", size, err)
		}
		return fmt.Sprintf("%s%s%sJSON%s.", proto, major, minor, sz), nil
	default:
		return "", fmt.Errorf("CESR %s is not a version this package knows how to build", v)
	}
}

// versionPattern matches either encoding. Anchoring on both is what lets an
// event's own bytes say which version it is, rather than the caller guessing.
var versionPattern = regexp.MustCompile(
	`(?:KERI|ACDC)(?:[0-9a-f]{2}JSON[0-9a-f]{6}_|[A-Za-z0-9_-]{3}JSON[A-Za-z0-9_-]{4}\.)`)

// ParseVersionString reads a version string back into its parts.
//
// This is why no protocol negotiation is needed to READ an event: the version
// is the first field of the event itself, at a fixed offset, so an implementation
// that supports both never has to attempt one encoding and fall back to the
// other. Trying 2.0 and retrying as 1.0 would be both unnecessary and unsafe —
// a malformed event of one version can resemble a valid event of the other.
func ParseVersionString(vs string) (proto Protocol, v Version, size int, err error) {
	switch {
	case len(vs) == 17 && strings.HasSuffix(vs, "_"):
		var major, minor, sz int
		p := vs[:4]
		if _, err = fmt.Sscanf(vs[4:], "%1x%1xJSON%6x_", &major, &minor, &sz); err != nil {
			return "", Version{}, 0, fmt.Errorf("%q is not a CESR 1.0 version string: %w", vs, err)
		}
		return Protocol(p), Version{Major: major, Minor: minor}, sz, nil

	case len(vs) == 16 && strings.HasSuffix(vs, "."):
		p := Protocol(vs[:4])
		major, err := b64Decode(vs[4:5])
		if err != nil {
			return "", Version{}, 0, fmt.Errorf("%q has an unreadable major version: %w", vs, err)
		}
		minor, err := b64Decode(vs[5:7])
		if err != nil {
			return "", Version{}, 0, fmt.Errorf("%q has an unreadable minor version: %w", vs, err)
		}
		if vs[7:11] != "JSON" {
			return "", Version{}, 0, fmt.Errorf("%q is not JSON-serialised", vs)
		}
		sz, err := b64Decode(vs[11:15])
		if err != nil {
			return "", Version{}, 0, fmt.Errorf("%q has an unreadable size: %w", vs, err)
		}
		return p, Version{Major: major, Minor: minor}, sz, nil

	default:
		return "", Version{}, 0, fmt.Errorf("%q is not a version string of either CESR version", vs)
	}
}

// DetectVersion reads which CESR version an event is written in, from the event.
//
// An agent talking to a stranger calls this and then dispatches. It does not
// need to know in advance, and it does not need the stranger to announce
// anything out of band.
func DetectVersion(raw []byte) (Protocol, Version, error) {
	if len(raw) < versionFieldOffset+16 {
		return "", Version{}, fmt.Errorf("too short to be an event: %d bytes", len(raw))
	}
	loc := versionPattern.FindIndex(raw)
	if loc == nil {
		return "", Version{}, fmt.Errorf("no version string, so this is not a CESR event")
	}
	if loc[0] != versionFieldOffset {
		return "", Version{}, fmt.Errorf("the version string is at offset %d, not %d, so this "+
			"is not a CESR event", loc[0], versionFieldOffset)
	}
	proto, v, _, err := ParseVersionString(string(raw[loc[0]:loc[1]]))
	return proto, v, err
}

// DefaultVersion is what this package builds when a caller does not say.
//
// It is V1, and moving it is a decision rather than a preference.
//
// CESR 1.0 is frozen. The same inputs produce byte-identical events across every
// keripy build from 1.1.17 to 2.0.0-dev6 — four releases spanning the 2.0
// development — which is what makes it safe to mint identities against.
//
// CESR 2.0 is not frozen yet. keripy 1.3.6 and keripy 2.0.0-dev6 disagree on
// EVERY 2.0 case in vectors/keri_vectors_v2_*.json, because the version string
// gained a second component between them:
//
//	1.3.6        KERICAAJSONAAEq.      16 characters
//	2.0.0-dev6   KERICAACAAJSONAAEt.   19 characters
//
// Different bytes mean different digests, so an identity minted under one form
// is a different identity under the other. A self-addressing identifier cannot
// be re-expressed once issued, so minting production identities at 2.0 before
// the format settles is the one mistake here that cannot be undone.
//
// Build V2 deliberately, for testing and for reading; do not make it the
// default until the reference stops moving.
var DefaultVersion = V1

// resolveVersion turns an unspecified version into the default and refuses one
// this package cannot build.
func resolveVersion(v Version) (Version, error) {
	if v == (Version{}) {
		v = DefaultVersion
	}
	if !v.Supported() {
		return Version{}, fmt.Errorf("CESR %s is not a version this package supports", v)
	}
	return v, nil
}
