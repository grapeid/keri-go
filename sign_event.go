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

// indexedSigQB64 renders a signature with the index of the key that made it.
//
// Indices above 63 need a wider code that this does not emit; refused rather
// than truncated, because an index silently wrapping to a different key would
// attribute a signature to the wrong holder.
func indexedSigQB64(sig []byte, index int) (string, error) {
	if len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("an Ed25519 signature is %d bytes, this one is %d",
			ed25519.SignatureSize, len(sig))
	}
	if index < 0 || index >= len(b64Alphabet) {
		return "", fmt.Errorf("key index %d cannot be written in a single CESR digit; "+
			"this package does not emit the wider form", index)
	}
	// "A" is the Ed25519 indexed-signature code; the second character is the
	// index of the signing key within the event's key list.
	code := "A" + string(b64Alphabet[index])
	return MatterQB64(code, sig)
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
// each signature is indexed by position. Passing them in a different order
// produces signatures attributed to the wrong keys — which fails verification
// rather than succeeding wrongly, but fails in a way that is hard to read, so it
// is worth stating.
//
// Every signature is verified against the event's own declared key at that index
// before the message is returned. That check costs one verification per
// signature and catches the entire class of bug where a signer is paired with
// the wrong key — locally, at the point of production, instead of remotely as an
// unexplained rejection.
func SignEvent(event []byte, signers ...Signer) (*SignedEvent, error) {
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
	if declaresKeys && len(signers) > len(ev.Keys) {
		return nil, fmt.Errorf("%d signers were given but the event declares %d keys",
			len(signers), len(ev.Keys))
	}

	sigs := make([]string, 0, len(signers))
	for i, s := range signers {
		if s == nil {
			return nil, fmt.Errorf("signer %d is missing", i)
		}
		pub, err := s.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("signer %d cannot report its public key: %w", i, err)
		}
		if declaresKeys && ev.Keys[i] != pub {
			return nil, fmt.Errorf("signer %d holds %s but the event declares %s at that "+
				"position, so the signature would be attributed to the wrong key",
				i, pub, ev.Keys[i])
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
		qb64, err := indexedSigQB64(raw, i)
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
