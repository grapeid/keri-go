package keri

import (
	"crypto/ed25519"
	"fmt"
)

// Turning an event and some signers into the bytes that travel.
//
// An event on its own is unauthenticated. What a peer accepts is the event
// followed by its attachments — a counted group of indexed signatures. The index
// matters: it says WHICH of the identity's keys produced each signature, which
// is what makes a threshold like 2-of-3 checkable.

// SignaturePlace is where an indexed signature counts.
//
// Index is the place in the event's key list of the key that signed. Ondex is
// the place in the PRIOR establishment event's next-key commitments that the
// same key opens, which is how a rotation reveals a committed key. They differ
// when a key sits at a different place in k than the commitment it opens: a
// partial rotation revealing the second commitment alone is Index 0, Ondex 1.
//
// CurrentOnly says the signature opens no prior commitment at all; Ondex is
// then ignored. Such a signature counts toward the signing threshold and
// nothing else. An interaction's signatures, and any signature by a key a
// rotation adds without having committed to it, are of that kind.
type SignaturePlace struct {
	Index       int
	Ondex       int
	CurrentOnly bool
}

// SamePlace is a signature whose key sits at the same place in both lists: the
// usual case, and what SignEvent writes.
func SamePlace(index int) SignaturePlace {
	return SignaturePlace{Index: index, Ondex: index}
}

// maxBigIndex is the largest place two CESR characters can hold.
const maxBigIndex = 64*64 - 1

// EncodeIndexedSignature writes an Ed25519 signature with the places it counts
// at, choosing the code exactly as keripy 1.3.6 does: "A" when both places are
// the same and fit one character, "2A" otherwise; "B" for a current-only
// signature whose index fits one character, "2B" otherwise.
func EncodeIndexedSignature(sig []byte, at SignaturePlace) (string, error) {
	if len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("an Ed25519 signature is %d bytes, this one is %d",
			ed25519.SignatureSize, len(sig))
	}
	// Refused rather than truncated: a place silently wrapping to a different
	// key would attribute a signature to the wrong holder.
	if at.Index < 0 || at.Index > maxBigIndex {
		return "", fmt.Errorf("key index %d cannot be written in an indexed signature; "+
			"the widest code holds 0..%d", at.Index, maxBigIndex)
	}
	two := func(n int) string {
		return string([]byte{b64Alphabet[n/64], b64Alphabet[n%64]})
	}
	var code string
	switch {
	case at.CurrentOnly && at.Index < 64:
		code = codeIdxCrtSig + string(b64Alphabet[at.Index])
	case at.CurrentOnly:
		code = codeIdxBigCrtSig + two(at.Index) + "AA"
	case at.Ondex < 0 || at.Ondex > maxBigIndex:
		return "", fmt.Errorf("prior-next place %d cannot be written in an indexed "+
			"signature; the widest code holds 0..%d", at.Ondex, maxBigIndex)
	case at.Ondex == at.Index && at.Index < 64:
		code = codeIdxSig + string(b64Alphabet[at.Index])
	default:
		code = codeIdxBigSig + two(at.Index) + two(at.Ondex)
	}
	return MatterQB64(code, sig)
}

// indexedSigQB64 renders a signature whose key sits at the same place in both
// lists.
func indexedSigQB64(sig []byte, index int) (string, error) {
	return EncodeIndexedSignature(sig, SamePlace(index))
}

// IndexedSignature is an indexed signature as read.
type IndexedSignature struct {
	// Code is the CESR code: "A", "B", "2A" or "2B".
	Code string
	// At is where it counts. CurrentOnly is set for "B" and "2B".
	At SignaturePlace
	// Raw is the 64-byte Ed25519 signature.
	Raw []byte
}

// ParseIndexedSignature reads one indexed Ed25519 signature in any of the four
// forms keripy 1.3.6 defines, refusing an unknown code, a value of the wrong
// length for its code, and a current-only signature that carries a prior-next
// place.
func ParseIndexedSignature(qb64 string) (IndexedSignature, error) {
	sig, err := readIndexedSig(qb64)
	if err != nil {
		return IndexedSignature{}, err
	}
	at := SignaturePlace{Index: sig.Index, Ondex: sig.Ondex, CurrentOnly: !sig.HasOndex}
	return IndexedSignature{Code: sig.Code, At: at, Raw: sig.Raw}, nil
}

// SignedEvent is an event with signatures attached, ready to send.
type SignedEvent struct {
	// Event is the canonical event bytes, exactly as signed.
	Event []byte
	// Attachment is the CESR attachment group.
	Attachment []byte
	// Message is Event followed by Attachment: what actually travels.
	Message []byte
}

// SignEvent signs an event with each of the given signers and frames the result.
//
// The signers must be in the same order as the keys the event declares, because
// each signature is indexed by position, and each opens the prior commitment at
// the same position. Use SignEventAt when a key's place in the prior commitment
// differs from its place in the event, or when a signature opens none.
//
// Every signature is verified against the event's own declared key at that index
// before the message is returned. That check costs one verification per
// signature and catches the entire class of bug where a signer is paired with
// the wrong key — locally, at the point of production, instead of remotely as an
// unexplained rejection.
func SignEvent(event []byte, signers ...Signer) (*SignedEvent, error) {
	placed := make([]PlacedSigner, len(signers))
	for i, s := range signers {
		placed[i] = PlacedSigner{Signer: s, At: SamePlace(i)}
	}
	return SignEventAt(event, placed...)
}

// PlacedSigner is a signer and the places its signature counts at.
type PlacedSigner struct {
	Signer Signer
	At     SignaturePlace
}

// SignEventAt signs an event with each signer at its stated places and frames
// the result.
//
// Where the event declares keys, each signer must hold the key at its Index;
// the signature is verified under it before anything is returned. Whether Ondex
// names the right prior commitment cannot be checked here, because the prior
// event is not among the arguments; ValidateSignedKEL checks it.
func SignEventAt(event []byte, signers ...PlacedSigner) (*SignedEvent, error) {
	if len(event) == 0 {
		return nil, fmt.Errorf("there is no event to sign")
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("an event with no signature attests to nothing; supply " +
			"at least one signer")
	}
	ev, err := ParseEvent(event)
	if err != nil {
		return nil, fmt.Errorf("refusing to sign bytes that are not a readable event: %w", err)
	}
	// An establishment event declares the keys it is signed under, so each
	// signer can be checked against the key at its index. A non-establishment
	// event — an interaction — declares no keys at all: it is signed by whatever
	// key state is in force, which lives in the log rather than in the event. So
	// the cross-check applies only where there is something to check against,
	// and requiring keys here would refuse to sign the very events that carry
	// delegation approvals and credential issuances.
	declaresKeys := len(ev.Keys) > 0

	sigs := make([]string, 0, len(signers))
	for i, p := range signers {
		s := p.Signer
		if s == nil {
			return nil, fmt.Errorf("signer %d is missing", i)
		}
		pub, err := s.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("signer %d cannot report its public key: %w", i, err)
		}
		if declaresKeys {
			if p.At.Index < 0 || p.At.Index >= len(ev.Keys) {
				return nil, fmt.Errorf("signer %d signs at key %d but the event declares %d keys",
					i, p.At.Index, len(ev.Keys))
			}
			if ev.Keys[p.At.Index] != pub {
				return nil, fmt.Errorf("signer %d holds %s but the event declares %s at that "+
					"position, so the signature would be attributed to the wrong key",
					i, pub, ev.Keys[p.At.Index])
			}
		}
		raw, err := s.Sign(event)
		if err != nil {
			return nil, fmt.Errorf("signer %d could not sign: %w", i, err)
		}
		// Verify what we just produced. A signer backed by hardware can fail in
		// ways software cannot, and an unverifiable signature is better found
		// here than by the peer that rejects it.
		if err := VerifySignature(pub, event, raw); err != nil {
			return nil, fmt.Errorf("signer %d produced a signature that does not verify "+
				"under its own key: %w", i, err)
		}
		qb64, err := EncodeIndexedSignature(raw, p.At)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, qb64)
	}

	attachment, err := AttachControllerSigs(sigs)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(event)+len(attachment))
	msg = append(msg, event...)
	msg = append(msg, attachment...)
	return &SignedEvent{Event: event, Attachment: attachment, Message: msg}, nil
}
