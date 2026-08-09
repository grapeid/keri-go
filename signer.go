package keri

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
)

// Holding keys, and signing with them.
//
// The central decision here is that this package never requires possession of a
// private key. It asks something else to sign.
//
// That is not a stylistic preference. On a secure enclave, a Trusted Platform
// Module, or a hardware security module, the private key CANNOT be exported —
// that is the entire point of the hardware. An interface shaped as "give me your
// seed and I will sign" is unusable with any of them, and a library that
// demanded one would have to be rewritten the day the hardware arrives. An
// interface shaped as "here are some bytes, give me a signature" works with
// software keys today and enclave keys later, with nothing in this package
// changing.
//
// So: Signer is what the package depends on, SoftwareSigner is the
// implementation for tests and for hosts with no secure hardware, and an enclave
// implementation lives outside this package and satisfies the same interface.

// Signer produces signatures over key events.
//
// Implementations are not required to be able to reveal their private key, and
// most interesting ones cannot.
type Signer interface {
	// PublicKey returns the verifying key in CESR qb64 form, carrying the code
	// that says whether the identity it belongs to may rotate.
	PublicKey() (string, error)
	// Sign returns a raw Ed25519 signature over exactly these bytes.
	//
	// Exactly these bytes: a KERI signature covers the canonical serialisation
	// of an event, so an implementation that hashes, wraps, or re-encodes what
	// it is given produces a signature no other implementation will accept.
	Sign(data []byte) ([]byte, error)
}

// SoftwareSigner holds an Ed25519 private key in this process's memory.
//
// Appropriate for tests, for development, and for hosts with no secure hardware.
// It is NOT appropriate for a production identity on a machine where the key
// could be read out of memory or off disk — for that, supply a Signer backed by
// hardware. This type deliberately has no method that returns the private key,
// so passing one around does not spread the material any further than the
// process that created it.
type SoftwareSigner struct {
	priv ed25519.PrivateKey
	// transferable says whether the identity this key belongs to may rotate.
	//
	// It changes the CESR code on the public key, and it is not cosmetic: a
	// non-transferable identifier IS its key, so nothing can ever rotate it. A
	// witness key is non-transferable; a controller key is not.
	transferable bool
}

// NewSoftwareSigner builds a signer from a 32-byte Ed25519 seed.
//
// The seed is expanded immediately and not retained, so the caller's copy is
// the only one it needs to look after.
func NewSoftwareSigner(seed []byte, transferable bool) (*SoftwareSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("an Ed25519 seed is %d bytes, this one is %d",
			ed25519.SeedSize, len(seed))
	}
	return &SoftwareSigner{
		priv:         ed25519.NewKeyFromSeed(seed),
		transferable: transferable,
	}, nil
}

// GenerateSigner makes a new key from the system's randomness.
func GenerateSigner(transferable bool) (*SoftwareSigner, error) {
	return GenerateSignerFrom(rand.Reader, transferable)
}

// GenerateSignerFrom makes a new key from a supplied source of randomness.
//
// Separate from GenerateSigner so that a test can be deterministic without the
// production path ever taking a source that might not be random. Do not pass
// anything but crypto/rand.Reader outside a test: a predictable seed is a
// predictable identity.
func GenerateSignerFrom(r io.Reader, transferable bool) (*SoftwareSigner, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("could not read %d bytes of randomness for a new key: %w",
			ed25519.SeedSize, err)
	}
	return NewSoftwareSigner(seed, transferable)
}

// PublicKey returns the verifying key in CESR qb64 form.
func (s *SoftwareSigner) PublicKey() (string, error) {
	if s == nil || s.priv == nil {
		return "", fmt.Errorf("this signer holds no key")
	}
	code := CodeEd25519
	if !s.transferable {
		code = CodeEd25519N
	}
	pub, ok := s.priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("the key held is not Ed25519")
	}
	return MatterQB64(code, pub)
}

// Sign returns a raw Ed25519 signature over exactly the bytes given.
func (s *SoftwareSigner) Sign(data []byte) ([]byte, error) {
	if s == nil || s.priv == nil {
		return nil, fmt.Errorf("this signer holds no key")
	}
	if len(data) == 0 {
		// Signing nothing produces a valid signature over nothing, which is a
		// signature an attacker can reuse anywhere. Refused rather than
		// produced.
		return nil, fmt.Errorf("refusing to sign an empty message")
	}
	return ed25519.Sign(s.priv, data), nil
}

// NextDigest is the pre-rotation commitment for a key: the digest a current
// event carries in place of the key it will rotate to.
//
// Pre-rotation is what stops a stolen current key from being enough to take an
// identity over. The next key is committed to by digest and never appears in
// the log until the rotation that uses it, so an attacker who holds the current
// key still cannot produce a rotation anyone will accept.
//
// The digest is taken over the qb64 public key TEXT, not over the raw key
// bytes. That distinction is the whole commitment: digesting the wrong one
// produces a value that looks right, is the right length, and matches nothing
// any other implementation computes.
func NextDigest(publicKeyQB64 string) (string, error) {
	if publicKeyQB64 == "" {
		return "", fmt.Errorf("there is no key to commit to")
	}
	return Blake3SAID([]byte(publicKeyQB64))
}

// VerifySignature checks a raw signature against a qb64 public key.
//
// Accepts either key code: a transferable controller key or a non-transferable
// witness key both verify the same way, and refusing one of them here would
// make witness receipts uncheckable.
func VerifySignature(publicKeyQB64 string, data, signature []byte) error {
	pub, err := MatterRaw(CodeEd25519, publicKeyQB64, ed25519.PublicKeySize)
	if err != nil {
		pub, err = MatterRaw(CodeEd25519N, publicKeyQB64, ed25519.PublicKeySize)
	}
	if err != nil {
		return fmt.Errorf("%q is not a readable Ed25519 public key: %w", publicKeyQB64, err)
	}
	if !ed25519.Verify(pub, data, signature) {
		return fmt.Errorf("the signature does not verify under %s, so whoever produced "+
			"it did not hold that key", publicKeyQB64)
	}
	return nil
}
