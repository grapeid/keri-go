//go:build pqtest

package keri

import "github.com/cloudflare/circl/sign/mldsa/mldsa65"

// Provisional post-quantum codes, read only by a build with the "pqtest" tag,
// so stage two of a hybrid identity (ADR-061 section 6) can be built and
// tested before CESR assigns codes. A production build reads none of them.
//
// CodeMLDSA65Key is the draft code CESR's v1.1 branch gives an ML-DSA-65
// public key, the one identity-bot commits to today, so a commitment made now
// opens under it. CodeMLDSA65IndexedSig is not CESR's: no indexed post-quantum
// signature code exists (CESR issue #171). It is a two-character code, three
// characters of index and three of prior-next place, so the 3309-byte
// signature, a multiple of three, fills whole quadruples with no lead byte.
const (
	CodeMLDSA65Key        = "2AAE"
	CodeMLDSA65IndexedSig = "3Z"
)

func init() {
	extraKeyCodes[CodeMLDSA65Key] = keyAlgorithm{
		RawLen:  mldsa65.PublicKeySize,
		SigCode: CodeMLDSA65IndexedSig,
		SigLen:  mldsa65.SignatureSize,
		Verify: func(pub, msg, sig []byte) bool {
			var pk mldsa65.PublicKey
			if pk.UnmarshalBinary(pub) != nil {
				return false
			}
			return mldsa65.Verify(&pk, msg, nil, sig)
		},
	}
	extraIndexedSigCodes[CodeMLDSA65IndexedSig] = indexedSigCode{
		IndexChars: 3, OndexChars: 3, RawLen: mldsa65.SignatureSize,
	}
}

// EncodeMLDSA65IndexedSignature writes an ML-DSA-65 signature at the places it
// counts, under the provisional indexed code.
func EncodeMLDSA65IndexedSignature(sig []byte, at SignaturePlace) (string, error) {
	three := func(n int) string {
		return string([]byte{b64Alphabet[n/4096%64], b64Alphabet[n/64%64], b64Alphabet[n%64]})
	}
	ondex := at.Ondex
	if at.CurrentOnly {
		ondex = at.Index
	}
	return MatterQB64Sized(CodeMLDSA65IndexedSig+three(at.Index)+three(ondex), sig)
}
