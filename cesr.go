package keri

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/zeebo/blake3"
)

// CESR is how KERI writes binary values as text.
//
// A value carries a short code saying what it is, and the code is part of the
// value rather than metadata beside it — so a digest and a public key of the
// same length are still told apart by anything reading them. The codes are
// normative: an implementation that emits a different prefix produces values
// nothing else can read.
//
// Implemented here rather than imported so this package depends on nothing but
// a hash function. It is meant to be usable by anyone, including offered
// upstream, and a library that reaches into an application's internals cannot
// be either.

// Code lengths are fixed by the table, and the encoding depends on the length.
// A one-character code pads the raw bytes by one and replaces the leading
// character of the base64; a four-character code is a plain prefix. Decoding one
// with the other's rules yields bytes that are wrong rather than an error, which
// is the failure worth designing out.
const (
	// CodeBlake3_256 marks a 32-byte Blake3 digest — the code every
	// self-addressing identifier carries.
	CodeBlake3_256 = "E"
	// CodeEd25519 marks a transferable Ed25519 public key: an identity that
	// may rotate.
	CodeEd25519 = "D"
	// CodeEd25519N marks a non-transferable one: an identifier that IS its key
	// and can never rotate. Witnesses are named this way, so a receipt can be
	// checked by anyone holding the identifier and nothing else.
	CodeEd25519N = "B"
	// CodeEd25519Sig marks a signature.
	CodeEd25519Sig = "0B"
	// CodeEd25519Seed marks an Ed25519 private-key seed.
	CodeEd25519Seed = "A"
)

// MatterQB64 encodes raw bytes with a CESR code.
//
// The padding rule is the part worth stating: base64 works in three-byte
// groups, so the raw value is left-padded to a multiple of three and the code
// then replaces exactly the characters that padding produced. That is why a
// 32-byte value with a one-character code comes out 44 characters, and why
// getting the pad wrong shifts every subsequent character.
func MatterQB64(code string, raw []byte) (string, error) {
	if code == "" {
		return "", fmt.Errorf("a CESR value must carry a code saying what it is")
	}
	pad := (3 - (len(raw) % 3)) % 3
	padded := make([]byte, pad+len(raw))
	copy(padded[pad:], raw)
	encoded := base64.RawURLEncoding.EncodeToString(padded)
	drop := len(code) % 4
	if drop > len(encoded) {
		return "", fmt.Errorf("cannot encode %d bytes with the %q code", len(raw), code)
	}
	return code + encoded[drop:], nil
}

// MatterRaw recovers the bytes from a CESR value, checking the code.
//
// The code is checked rather than skipped. Values of different types are the
// same shape once the prefix is removed, so decoding one without checking what
// it claims to be is how a digest gets read as a key.
//
// It reads only the canonical spelling, so each value has exactly one string.
// That matters wherever a value is compared or counted as text — an identifier
// is a key, a witness is counted once — and a reader that accepts a second
// spelling of the same bytes lets one party appear as two. Three things would
// otherwise give a value more than one string:
//
//   - the lead bits. The code stands in for the lead bytes, but a code
//     character carries 6 bits and a lead byte 8, so the character after the
//     code carries the rest of the lead bytes. Unchecked, a one-character code
//     gave every value 4 spellings and a two-character code 16;
//   - characters outside base64url. The standard decoder skips line breaks,
//     so a value with one inserted read as the same bytes;
//   - the length. A qb64 value is always a whole number of four-character
//     groups, and exactly as long as its code and size make it.
//
// An Ed25519 key ("D" or "B") must also be a key: a point on the curve, in its
// canonical encoding, of large order (CheckEd25519PublicKey). Every key read
// from a log, an event or a receipt comes through here, so none escapes it.
func MatterRaw(code, qb64 string, expectLen int) ([]byte, error) {
	if code == "" || len(qb64) < len(code) || qb64[:len(code)] != code {
		return nil, fmt.Errorf("expected a %q value, got one starting %.4q", code, qb64)
	}
	if len(qb64)%4 != 0 {
		return nil, fmt.Errorf("%q value is %d characters, not a whole number of "+
			"four-character groups, so it is not qb64", code, len(qb64))
	}
	if !isBase64URL(qb64[len(code):]) {
		return nil, fmt.Errorf("%q value has a character outside base64url, so it is not qb64", code)
	}
	pad := len(code) % 4
	if expectLen > 0 {
		if want := len(code) - pad + (pad+expectLen)*4/3; (pad+expectLen)%3 != 0 || len(qb64) != want {
			return nil, fmt.Errorf("a %q value of %d bytes is %d characters, this one is %d",
				code, expectLen, want, len(qb64))
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(padChars(pad) + qb64[len(code):])
	if err != nil {
		return nil, fmt.Errorf("%q value is not valid base64url: %w", code, err)
	}
	if len(decoded) < pad {
		return nil, fmt.Errorf("%q value is too short to hold anything", code)
	}
	for _, b := range decoded[:pad] {
		if b != 0 {
			return nil, fmt.Errorf("%q value's lead bits are not zero, so it is not "+
				"the canonical spelling of any value", code)
		}
	}
	raw := decoded[pad:]
	if expectLen > 0 && len(raw) != expectLen {
		return nil, fmt.Errorf("expected %d bytes for a %q value, got %d", expectLen, code, len(raw))
	}
	if code == CodeEd25519 || code == CodeEd25519N {
		if err := CheckEd25519PublicKey(raw); err != nil {
			return nil, fmt.Errorf("%q value: %w", code, err)
		}
	}
	return raw, nil
}

// isBase64URL reports whether every character of s is in the base64url
// alphabet, the only one qb64 uses. Padding is not in it, and nor are the line
// breaks the standard decoder would otherwise skip.
func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func padChars(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'A'
	}
	return string(out)
}

// Blake3SAID returns the self-addressing identifier of some bytes.
//
// This is the function an identity ultimately rests on: an identifier is the
// digest of the event that created it, so changing any byte of that event
// changes who the identity is.
func Blake3SAID(data []byte) (string, error) {
	sum := blake3.Sum256(data)
	return MatterQB64(CodeBlake3_256, sum[:])
}

// MatterQB64Sized encodes raw under code where the code is a whole number of
// four-character groups, or its length past one matches the lead bytes the
// raw size needs: the raw bytes are left-padded with zero bytes to a multiple
// of three, and the code replaces as many leading characters of their base64
// as its length past a multiple of four. For a four-character code and a raw
// size of 2 mod 3, such as an ML-DSA-65 key, that keeps the lead byte the
// encoding needs, which MatterQB64's one rule for every code would drop. A
// code whose length does not fit the raw size is refused: replacing a data
// character with a code character would change the value with no error.
func MatterQB64Sized(code string, raw []byte) (string, error) {
	if code == "" {
		return "", fmt.Errorf("a CESR value must carry a code saying what it is")
	}
	lead := (3 - len(raw)%3) % 3
	if d := len(code) % 4; d != 0 && d != lead {
		return "", fmt.Errorf("a %d-character code cannot carry %d bytes: it would replace "+
			"%d characters where the value has %d lead bytes", len(code), len(raw), d, lead)
	}
	padded := make([]byte, lead+len(raw))
	copy(padded[lead:], raw)
	full := base64.RawURLEncoding.EncodeToString(padded)
	drop := len(code) % 4
	if drop > len(full) {
		return "", fmt.Errorf("cannot encode %d bytes with the %q code", len(raw), code)
	}
	return code + full[drop:], nil
}

// MatterRawSized reads a value MatterQB64Sized wrote: exactly rawLen bytes
// under code, its lead bytes zero, in its one canonical spelling.
func MatterRawSized(code, qb64 string, rawLen int) ([]byte, error) {
	if code == "" || len(qb64) < len(code) || qb64[:len(code)] != code {
		return nil, fmt.Errorf("expected a %q value, got one starting %.4q", code, qb64)
	}
	lead := (3 - rawLen%3) % 3
	drop := len(code) % 4
	if drop != 0 && drop != lead {
		return nil, fmt.Errorf("a %d-character code cannot carry %d bytes", len(code), rawLen)
	}
	if want := len(code) - drop + (lead+rawLen)/3*4; len(qb64) != want {
		return nil, fmt.Errorf("%q value is %d characters, and %d bytes under it are %d",
			code, len(qb64), rawLen, want)
	}
	body := qb64[len(code):]
	if !isBase64URL(body) {
		return nil, fmt.Errorf("%q value has a character outside base64url, so it is not qb64", code)
	}
	full := strings.Repeat("A", drop) + body
	padded, err := base64.RawURLEncoding.Strict().DecodeString(full)
	if err != nil {
		return nil, fmt.Errorf("%q value is not base64url: %w", code, err)
	}
	for _, b := range padded[:lead] {
		if b != 0 {
			return nil, fmt.Errorf("%q value's lead bytes are not zero, so it is not "+
				"the canonical spelling of its value", code)
		}
	}
	return padded[lead:], nil
}
