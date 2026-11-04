package keri

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
)

// The key and signature codes this package reads beyond Ed25519's.
//
// A production build reads no post-quantum code: an establishment event
// naming a key under a code this package does not read is refused, and so is
// a signature under an unknown code. A build with the "kerigo_pqtest" tag
// registers the provisional post-quantum codes (pq_test_codes.go), so that a
// key committed to under them now can be revealed, and a chain signed by both
// kinds verified, in tests, before CESR assigns them. Nothing reads them in
// production until it does (K4, K9). The tag is namespaced because Go build
// tags reach every module in a build; PostQuantumTestCodes says whether a
// build has them, and SelfTest fails when it does.
//
// Keys under the ECDSA codes keripy 1.3.6 reads (secp256k1 "1AAA"/"1AAB",
// secp256r1 "1AAI"/"1AAJ") are read as keys, as keripy reads them, though this
// package verifies no ECDSA signature: such a key's signature never counts
// here. An event keripy accepts on its Ed25519 signatures alone is accepted
// here too; one that needs an ECDSA signature to meet its threshold is not, a
// divergence from keripy recorded by the test that pins it.

// keyAlgorithm is how keys under one code are read and their signatures
// checked.
type keyAlgorithm struct {
	// RawLen is the key's size in bytes.
	RawLen int
	// SigCodes are the indexed signature codes its signatures carry.
	SigCodes []string
	// Verify checks sig over msg under the raw key pub; nil for an Ed25519
	// key, and for a key this package reads but verifies no signature of.
	Verify func(pub, msg, sig []byte) bool
	// Unverified marks a key read but never verified (ECDSA).
	Unverified bool
}

// indexedSigCode is an indexed signature code: the characters after the code
// that hold the key's place and the prior-next place, and the signature's
// size.
type indexedSigCode struct {
	IndexChars, OndexChars int
	RawLen                 int
	// CurrentOnly marks a code whose signatures open no prior commitment:
	// its ondex characters must be zero.
	CurrentOnly bool
}

// Width is how many characters a signature under code occupies.
func (c indexedSigCode) width(code string) int {
	prefix := len(code) + c.IndexChars + c.OndexChars
	lead := (3 - c.RawLen%3) % 3
	return prefix - prefix%4 + (lead+c.RawLen)/3*4
}

var (
	extraKeyCodes        = map[string]keyAlgorithm{}
	extraIndexedSigCodes = map[string]indexedSigCode{}

	// ecdsaKeyCodes are the ECDSA key codes keripy 1.3.6 reads, each a
	// 33-byte compressed point.
	ecdsaKeyCodes = []string{"1AAA", "1AAB", "1AAI", "1AAJ"}
)

// PostQuantumTestCodes reports whether this build reads the provisional
// post-quantum codes: true only in a build with the "kerigo_pqtest" tag,
// which must never be a production one.
func PostQuantumTestCodes() bool { return len(extraKeyCodes) > 0 }

// longestFirst are a registry's codes, longest first, so a code that is a
// prefix of another is tried after it and a match does not depend on map
// order.
func longestFirst[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// keyCodeOf is the code of key and how it is read: Ed25519 under "D" or "B",
// or a registered code. ok is false for a key under no code this build reads.
func keyCodeOf(key string) (code string, alg keyAlgorithm, ok bool) {
	for _, c := range longestFirst(extraKeyCodes) {
		a := extraKeyCodes[c]
		if strings.HasPrefix(key, c) {
			if _, err := MatterRawSized(c, key, a.RawLen); err == nil {
				return c, a, true
			}
		}
	}
	for _, c := range ecdsaKeyCodes {
		if strings.HasPrefix(key, c) {
			if _, err := MatterRawSized(c, key, 33); err == nil {
				return c, keyAlgorithm{RawLen: 33, Unverified: true}, true
			}
		}
	}
	for _, c := range []string{CodeEd25519, CodeEd25519N} {
		if _, err := MatterRaw(c, key, ed25519.PublicKeySize); err == nil {
			return c, keyAlgorithm{RawLen: ed25519.PublicKeySize}, true
		}
	}
	return "", keyAlgorithm{}, false
}

// checkKeyCodes refuses an establishment event naming a key this build cannot
// read: under an unknown code, or the wrong length for its code. A digest in
// n is not read here; it stays opaque until a key opens it.
func checkKeyCodes(fs *faults, ev *Event) {
	if !ev.Establishment() {
		return
	}
	for i, key := range ev.Keys {
		if _, _, ok := keyCodeOf(key); !ok {
			fs.add(FaultMalformed, "key %d (%.12s…) is under no code this build reads, "+
				"or is the wrong length for its code", i, key)
		}
	}
}

// extraIndexedSigWidth is the width of a signature under a registered indexed
// code at the start of s, or 0 where s starts with none.
func extraIndexedSigWidth(s string) (string, int) {
	for _, code := range longestFirst(extraIndexedSigCodes) {
		if strings.HasPrefix(s, code) {
			return code, extraIndexedSigCodes[code].width(code)
		}
	}
	return "", 0
}

// readExtraIndexedSig reads a signature under a registered indexed code.
func readExtraIndexedSig(code, qb64 string) (indexedSig, error) {
	c := extraIndexedSigCodes[code]
	if len(qb64) != c.width(code) {
		return indexedSig{}, fmt.Errorf("an indexed signature with code %q is %d characters, "+
			"this one is %d", code, c.width(code), len(qb64))
	}
	sig := indexedSig{QB64: qb64, Code: code}
	at := len(code)
	var err error
	if sig.Index, err = b64Int(qb64[at : at+c.IndexChars]); err != nil {
		return indexedSig{}, fmt.Errorf("the signature's index is not readable: %w", err)
	}
	at += c.IndexChars
	if c.OndexChars > 0 {
		ondex, err := b64Int(qb64[at : at+c.OndexChars])
		if err != nil {
			return indexedSig{}, fmt.Errorf("the signature's prior-next place is not readable: %w", err)
		}
		if c.CurrentOnly {
			// As for 2B: a current-only signature has no second place, and a
			// non-zero one would be a second spelling of the same signature.
			if ondex != 0 {
				return indexedSig{}, fmt.Errorf("a current-only signature (%s) carries no "+
					"prior-next place, and this one carries %d", code, ondex)
			}
		} else {
			sig.Ondex, sig.HasOndex = ondex, true
		}
	}
	head := qb64[:len(code)+c.IndexChars+c.OndexChars]
	raw, err := MatterRawSized(head, qb64, c.RawLen)
	if err != nil {
		return indexedSig{}, fmt.Errorf("the attached signature is not readable: %w", err)
	}
	sig.Raw = raw
	return sig, nil
}

// VerifyUnderKey checks one signature over msg under key, by the key's code:
// an Ed25519 key ("D" or "B") takes an Ed25519 signature, and a registered
// key (ML-DSA-65, in a build with the "kerigo_pqtest" tag only) the signature
// it was registered with. A build without the tag refuses a post-quantum key
// outright, as it refuses to read one.
//
// sigCode is the signature's indexed code ("A", "B", "2A", "2B", or a
// registered one), or "" for a raw signature that carries none. A signature
// whose code does not fit the key's, such as an Ed25519 one offered for an
// ML-DSA-65 key, is refused, and so is a raw signature of the wrong size for
// the key. A nil error means the signature verifies; every other outcome is
// an error saying why.
func VerifyUnderKey(key string, msg []byte, sigCode string, sig []byte) error {
	code, alg, ok := keyCodeOf(key)
	if !ok {
		return fmt.Errorf("%.12s… is under no code this build reads, or is the wrong length for its code", key)
	}
	if alg.Unverified {
		return fmt.Errorf("this package verifies no signature under the ECDSA key %.12s…", key)
	}
	if alg.Verify == nil {
		if _, extra := extraIndexedSigCodes[sigCode]; extra {
			return fmt.Errorf("a signature under code %q does not fit the Ed25519 key %.12s…", sigCode, key)
		}
		pub, err := MatterRaw(code, key, ed25519.PublicKeySize)
		if err != nil {
			return fmt.Errorf("%q is not a readable Ed25519 public key: %w", key, err)
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
			return fmt.Errorf("the signature does not verify under %s, so whoever produced "+
				"it did not hold that key", key)
		}
		return nil
	}
	if sigCode != "" {
		carried := false
		for _, c := range alg.SigCodes {
			carried = carried || sigCode == c
		}
		if !carried {
			return fmt.Errorf("a signature under code %q does not fit the key %.12s…", sigCode, key)
		}
	}
	pub, err := MatterRawSized(code, key, alg.RawLen)
	if err != nil {
		return fmt.Errorf("%q is not a readable public key: %w", key, err)
	}
	if !alg.Verify(pub, msg, sig) {
		return fmt.Errorf("the signature does not verify under %s, so whoever produced "+
			"it did not hold that key", key)
	}
	return nil
}

// verifyIndexedSig checks sig over msg under key with VerifyUnderKey. A
// signature that does not verify is (false, nil), as before; a key this build
// cannot read is an error.
func verifyIndexedSig(key string, msg []byte, sig indexedSig) (bool, error) {
	if _, _, ok := keyCodeOf(key); !ok {
		return false, fmt.Errorf("the key is under no code this build reads")
	}
	return VerifyUnderKey(key, msg, sig.Code, sig.Raw) == nil, nil
}
