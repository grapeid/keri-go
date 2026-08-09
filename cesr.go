package keri

import (
	"encoding/base64"
	"fmt"

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
func MatterRaw(code, qb64 string, expectLen int) ([]byte, error) {
	if len(qb64) < len(code) || qb64[:len(code)] != code {
		return nil, fmt.Errorf("expected a %q value, got one starting %.4q", code, qb64)
	}
	pad := len(code) % 4
	decoded, err := base64.RawURLEncoding.DecodeString(
		string(make([]byte, 0, pad)) + padChars(pad) + qb64[len(code):])
	if err != nil {
		return nil, fmt.Errorf("%q value is not valid base64url: %w", code, err)
	}
	if len(decoded) < pad {
		return nil, fmt.Errorf("%q value is too short to hold anything", code)
	}
	raw := decoded[pad:]
	if expectLen > 0 && len(raw) != expectLen {
		return nil, fmt.Errorf("expected %d bytes for a %q value, got %d", expectLen, code, len(raw))
	}
	return raw, nil
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
