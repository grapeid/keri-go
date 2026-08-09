package keri

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// What makes a transaction event transmissible.
//
// A registry inception, a credential issuance and a revocation are not
// self-standing claims. Each one asserts that something happened, and the thing
// that makes that assertion worth anything is the issuer's key log: the issuer
// anchors the transaction event's digest in one of its own events, and that
// anchor is what a verifier checks.
//
// So a transaction event never travels alone. It carries a SOURCE SEAL COUPLE
// naming the anchoring event — its sequence number in the issuer's log, and its
// digest. Without that, a receiver has an event with no way to find the
// authority for it.
//
// This was the gap that stopped keripy accepting anything from the credential
// side of this package. Worth noting how it presented: keripy did not refuse a
// bare transaction event, it BLOCKED, because the CESR parser knows an
// attachment should follow and waits for it. A hang, not an error.

// CodeSeqner marks a sequence number written as a CESR primitive: 128 bits, so
// that a sequence number is a fixed width whatever its value. Its width is
// sizeSeqner, declared with the other attachment sizes in validation.go.
const CodeSeqner = "0A"

// CounterSealSourceCouples introduces a group of source seal couples.
const CounterSealSourceCouples = "-G"

// SourceSeal names the event in a key log that anchors a transaction event.
type SourceSeal struct {
	// SN is the sequence number of the anchoring event in the issuer's log.
	SN uint64
	// SAID is the digest of that anchoring event.
	SAID string
}

// SeqnerQB64 renders a sequence number as CESR writes it.
//
// Fixed at 128 bits regardless of the value, which is why sequence number one
// is twenty-four characters rather than two. A variable-width encoding would
// make the attachment's length depend on its contents, and the parser reads by
// width.
func SeqnerQB64(sn uint64) (string, error) {
	raw := make([]byte, 16)
	binary.BigEndian.PutUint64(raw[8:], sn)
	return MatterQB64(CodeSeqner, raw)
}

// SeqnerFromQB64 reads a sequence number back.
func SeqnerFromQB64(qb64 string) (uint64, error) {
	raw, err := MatterRaw(CodeSeqner, qb64, 16)
	if err != nil {
		return 0, fmt.Errorf("not a readable sequence number: %w", err)
	}
	// The high eight bytes are the part of the 128-bit range this package does
	// not use. Refused rather than truncated: silently dropping them would read
	// a sequence number as a different, smaller one.
	if binary.BigEndian.Uint64(raw[:8]) != 0 {
		return 0, fmt.Errorf("sequence number %q is larger than this package can "+
			"represent", qb64)
	}
	return binary.BigEndian.Uint64(raw[8:]), nil
}

// AttachSourceSeals frames a group of source seal couples.
func AttachSourceSeals(seals []SourceSeal) ([]byte, error) {
	if len(seals) == 0 {
		return nil, fmt.Errorf("a source seal group needs at least one seal")
	}
	frame, err := counterFrame(CounterSealSourceCouples, len(seals))
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(frame)
	for i, s := range seals {
		if len(s.SAID) != saidPlaceholderLen {
			return nil, fmt.Errorf("seal %d names an anchoring event whose digest is %d "+
				"characters, not %d", i, len(s.SAID), saidPlaceholderLen)
		}
		sn, err := SeqnerQB64(s.SN)
		if err != nil {
			return nil, fmt.Errorf("seal %d: %w", i, err)
		}
		b.WriteString(sn)
		b.WriteString(s.SAID)
	}
	return []byte(b.String()), nil
}

// AnchoredEvent returns a transaction event with its source seal attached: the
// bytes that actually travel.
//
// The seal must name the event in the ISSUER's key log that anchors this one.
// Getting it wrong does not corrupt anything locally — it produces a message
// whose authority cannot be found, which a receiver refuses.
func AnchoredEvent(event []byte, seal SourceSeal) ([]byte, error) {
	if len(event) == 0 {
		return nil, fmt.Errorf("there is no event to anchor")
	}
	attachment, err := AttachSourceSeals([]SourceSeal{seal})
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(event)+len(attachment))
	out = append(out, event...)
	out = append(out, attachment...)
	return out, nil
}

// ParseSourceSeals reads a source seal group back out of an attachment.
func ParseSourceSeals(attached []byte) ([]SourceSeal, error) {
	s := string(attached)
	if !strings.HasPrefix(s, CounterSealSourceCouples) {
		return nil, fmt.Errorf("these bytes do not begin with a source seal group")
	}
	if len(s) < 4 {
		return nil, fmt.Errorf("a counter is four characters, this is %d", len(s))
	}
	count, err := b64Int(s[2:4])
	if err != nil {
		return nil, fmt.Errorf("the source seal count is not readable: %w", err)
	}
	rest := s[4:]
	const coupleLen = sizeSeqner + saidPlaceholderLen
	if len(rest) != count*coupleLen {
		return nil, fmt.Errorf("the group says %d seals, which is %d characters, but %d "+
			"follow", count, count*coupleLen, len(rest))
	}
	out := make([]SourceSeal, 0, count)
	for i := 0; i < count; i++ {
		chunk := rest[i*coupleLen : (i+1)*coupleLen]
		sn, err := SeqnerFromQB64(chunk[:sizeSeqner])
		if err != nil {
			return nil, fmt.Errorf("seal %d: %w", i, err)
		}
		out = append(out, SourceSeal{SN: sn, SAID: chunk[sizeSeqner:]})
	}
	return out, nil
}
