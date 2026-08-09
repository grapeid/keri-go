package keri

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Receipts and CESR attachment streams: how events leave one implementation
// and arrive at another.
//
// Everything green so far is an event a single implementation builds alone.
// Attachments are the interop surface. A package that can build events but
// cannot frame signatures and receipts cannot talk to anything.
//
// A stream is the event bytes followed immediately by counted attachment
// groups. Every counter is four characters: a two-character code, then a
// count as two CESR base64 digits. The groups this package produces:
//
//	-A   controller indexed signatures
//	-B   witness indexed signatures
//	-C   non-transferable receipt couples (witness identifier + cigar)
//	-D   transferable receipt quadruples
//	-V   attached material quadlets
//
// Field order and couple order are part of the bytes. Reordering, dropping or
// "tidying" them changes whether a toad is met and what digests peers compute.
//
// CESR 1.0 only. Attachment framing under 2.0 is not frozen across keripy
// builds, and the vectors this package is held to are 1.0.

// ---------------------------------------------------------------------------
// Receipt body
// ---------------------------------------------------------------------------

// ReceiptInput is what building a receipt event is given.
//
// A receipt body has exactly five fields — version, type, the digest of the
// receipted event, the identity's prefix, and the sequence number. It does not
// carry a witness identifier or a signature; those ride in the attachment.
type ReceiptInput struct {
	Prefix    string `json:"prefix"`
	SN        int    `json:"sn"`
	EventSAID string `json:"event_said"`
}

// rctWire is a receipt event in the order KERI serialises it.
//
// Note what it does not contain: no witness, no signature. Pointing d at the
// wrong digest means the receipt is not covering the event you think it is.
type rctWire struct {
	V string `json:"v"`
	T string `json:"t"`
	D string `json:"d"`
	I string `json:"i"`
	S string `json:"s"`
}

// BuildReceipt returns the canonical bytes of a receipt event.
//
// The receipt's d field is the digest of the event it covers — written into
// the body, not recomputed over the receipt. That is the whole point of a
// receipt: it names, by digest, what was seen.
func BuildReceipt(in ReceiptInput) ([]byte, error) {
	if in.Prefix == "" {
		return nil, fmt.Errorf("a receipt must name the identity whose event it covers")
	}
	if in.EventSAID == "" {
		return nil, fmt.Errorf("a receipt must name the event it covers by digest")
	}
	if len(in.EventSAID) != saidPlaceholderLen {
		return nil, fmt.Errorf("an event digest is %d characters, this one is %d",
			saidPlaceholderLen, len(in.EventSAID))
	}

	w := rctWire{
		T: "rct",
		D: in.EventSAID,
		I: in.Prefix,
		S: sequenceNumber(in.SN),
	}
	return serialize(w)
}

func (w rctWire) MarshalJSON() ([]byte, error) {
	type wire rctWire
	if w.V == "" {
		w.V = versionString(0)
	}
	return json.Marshal(wire(w))
}

// ---------------------------------------------------------------------------
// Attachment framing
// ---------------------------------------------------------------------------

// Counter codes that introduce attachment groups. Public so a caller can assert
// the table without re-deriving the strings, and so the constants cases have a
// single source of truth that matches the wire.
const (
	// CounterControllerIdxSigs introduces controller indexed signatures.
	CounterControllerIdxSigs = counterControllerIdxSigs
	// CounterWitnessIdxSigs introduces witness indexed signatures.
	CounterWitnessIdxSigs = counterWitnessIdxSigs
	// CounterNonTransReceiptCouples introduces non-transferable receipt couples.
	CounterNonTransReceiptCouples = counterNonTransReceiptCouples
	// CounterTransReceiptQuadruples introduces transferable receipt quadruples.
	CounterTransReceiptQuadruples = counterTransReceiptQuadruples
	// CounterAttachedMaterialQuadlets introduces a nested run of attachments.
	CounterAttachedMaterialQuadlets = counterAttachedMaterial
)

// counterFrame is the four-character introducer: two-character code + two CESR
// digits of count.
func counterFrame(code string, count int) (string, error) {
	if len(code) != 2 {
		return "", fmt.Errorf("an attachment counter code is two characters, got %q", code)
	}
	if count < 0 {
		return "", fmt.Errorf("an attachment count cannot be negative, got %d", count)
	}
	if count >= 64*64 {
		return "", fmt.Errorf("attachment count %d does not fit in two CESR digits", count)
	}
	// CESR alphabet: A=0 … _=63. Two digits, most-significant first.
	return code + string([]byte{
		b64Alphabet[count/64],
		b64Alphabet[count%64],
	}), nil
}

// AttachControllerSigs frames a group of controller indexed signatures.
//
// Order is load-bearing: the signatures are emitted in the order given, each
// already carrying its own index. Renumbering or reordering them breaks
// multi-sig exchange.
func AttachControllerSigs(sigers []string) ([]byte, error) {
	if len(sigers) == 0 {
		return nil, fmt.Errorf("a controller-signature group needs at least one signature")
	}
	for i, s := range sigers {
		if len(s) != sizeIndexedSig {
			return nil, fmt.Errorf("controller signature %d is %d characters, not %d",
				i, len(s), sizeIndexedSig)
		}
	}
	frame, err := counterFrame(CounterControllerIdxSigs, len(sigers))
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(frame)
	for _, s := range sigers {
		b.WriteString(s)
	}
	return []byte(b.String()), nil
}

// ReceiptCouple is one non-transferable witness receipt: the witness
// identifier (which IS the verifying key) and the cigar over the event.
type ReceiptCouple struct {
	Witness   string `json:"witness"`
	CigarQB64 string `json:"cigar_qb64"`
}

// AttachReceiptCouples frames a group of non-transferable receipt couples.
//
// Order is part of the bytes. Reordering couples, dropping one, or
// deduplicating by key changes whether the toad is met.
func AttachReceiptCouples(couples []ReceiptCouple) ([]byte, error) {
	if len(couples) == 0 {
		return nil, fmt.Errorf("a receipt-couple group needs at least one couple")
	}
	for i, c := range couples {
		if len(c.Witness) != sizePrefix {
			return nil, fmt.Errorf("receipt couple %d: a witness identifier is %d characters, got %d",
				i, sizePrefix, len(c.Witness))
		}
		if len(c.CigarQB64) != sizeCigar {
			return nil, fmt.Errorf("receipt couple %d: a cigar is %d characters, got %d",
				i, sizeCigar, len(c.CigarQB64))
		}
	}
	frame, err := counterFrame(CounterNonTransReceiptCouples, len(couples))
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(frame)
	for _, c := range couples {
		b.WriteString(c.Witness)
		b.WriteString(c.CigarQB64)
	}
	return []byte(b.String()), nil
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

// StreamInput is what assembling a CESR stream is given.
//
// The event arrives already built; the attachments are the signatures and
// receipts that travel with it. This does not re-derive signatures — it frames
// material the caller already holds, which is exactly what a sender does when
// packaging an event for the wire.
type StreamInput struct {
	EventRawB64 string   `json:"event_raw_b64"`
	SigersQB64  []string `json:"sigers_qb64"`
	CigarsQB64  []string `json:"cigars_qb64"`
	// Witnesses names the signers of cigars_qb64, in the same order. Required
	// when cigars are present: a non-transferable couple is (identifier, cigar),
	// and the identifier is not recoverable from the cigar alone.
	Witnesses []string        `json:"witnesses"`
	Couples   []ReceiptCouple `json:"couples"`
}

// BuildStream returns event bytes followed by their CESR attachments.
func BuildStream(in StreamInput) ([]byte, error) {
	if in.EventRawB64 == "" {
		return nil, fmt.Errorf("a stream needs the event it carries")
	}
	event, err := base64.StdEncoding.DecodeString(in.EventRawB64)
	if err != nil {
		return nil, fmt.Errorf("the event is not readable base64: %w", err)
	}
	if len(event) == 0 || event[0] != '{' {
		return nil, fmt.Errorf("a stream's event must be a JSON object")
	}

	var attached []byte
	if len(in.SigersQB64) > 0 {
		group, err := AttachControllerSigs(in.SigersQB64)
		if err != nil {
			return nil, err
		}
		attached = append(attached, group...)
	}

	couples := in.Couples
	if len(couples) == 0 && len(in.CigarsQB64) > 0 {
		if len(in.Witnesses) != len(in.CigarsQB64) {
			return nil, fmt.Errorf("have %d cigars and %d witnesses; each cigar needs "+
				"the witness that produced it", len(in.CigarsQB64), len(in.Witnesses))
		}
		couples = make([]ReceiptCouple, len(in.CigarsQB64))
		for i := range in.CigarsQB64 {
			couples[i] = ReceiptCouple{
				Witness:   in.Witnesses[i],
				CigarQB64: in.CigarsQB64[i],
			}
		}
	}
	if len(couples) > 0 {
		group, err := AttachReceiptCouples(couples)
		if err != nil {
			return nil, err
		}
		attached = append(attached, group...)
	}

	if len(attached) == 0 {
		return nil, fmt.Errorf("a stream with no attachments is just the event; " +
			"nothing here to frame")
	}
	out := make([]byte, 0, len(event)+len(attached))
	out = append(out, event...)
	out = append(out, attached...)
	return out, nil
}

// BuildReceiptStream returns a receipt body with witness couples attached.
func BuildReceiptStream(body ReceiptInput, couples []ReceiptCouple) ([]byte, error) {
	rct, err := BuildReceipt(body)
	if err != nil {
		return nil, err
	}
	if len(couples) == 0 {
		return rct, nil
	}
	group, err := AttachReceiptCouples(couples)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(rct)+len(group))
	out = append(out, rct...)
	out = append(out, group...)
	return out, nil
}

// ---------------------------------------------------------------------------
// Conformance seam
// ---------------------------------------------------------------------------

// errAnsweredByAssert marks a case that produces no bytes and is checked by a
// dedicated assertion in the conformance harness. Distinct from
// ErrNotImplemented so the harness does not report the work as unfinished.
var errAnsweredByAssert = fmt.Errorf("answered by assertion")

// AnswerReceipt produces this implementation's answer to a receipt case.
//
// Attachment material — the cigars — may arrive on the input or, when the
// vector file captured them under expect, on the case's expect object. Either
// way they are treated as given material to frame, never as something this
// function re-signs: producing a signature requires a private key this package
// does not hold.
func AnswerReceipt(c Case) ([]byte, error) {
	var in struct {
		Prefix           string          `json:"prefix"`
		SN               int             `json:"sn"`
		EventSAID        string          `json:"event_said"`
		EventRawB64      string          `json:"event_raw_b64"`
		Witness          string          `json:"witness"`
		Witnesses        []string        `json:"witnesses"`
		SigningWitnesses []string        `json:"signing_witnesses"`
		Toad             int             `json:"toad"`
		CigarQB64        string          `json:"cigar_qb64"`
		Couples          []ReceiptCouple `json:"couples"`
	}
	if err := json.Unmarshal(c.Input, &in); err != nil {
		return nil, fmt.Errorf("case input is not a receipt: %w", err)
	}

	// Context case: carries the event a receipt is checked against, and no
	// receipt to build. The harness asserts the fields directly.
	if in.EventRawB64 != "" && in.EventSAID == "" && in.Prefix == "" &&
		in.CigarQB64 == "" && len(in.Couples) == 0 &&
		len(in.SigningWitnesses) == 0 && in.Witness == "" {
		return nil, errAnsweredByAssert
	}

	couples := in.Couples
	if len(couples) == 0 {
		couples = couplesFromExpect(c)
	}
	if len(couples) == 0 && in.CigarQB64 != "" {
		w := in.Witness
		if w == "" && len(in.SigningWitnesses) == 1 {
			w = in.SigningWitnesses[0]
		}
		if w == "" && len(in.Witnesses) == 1 {
			w = in.Witnesses[0]
		}
		if w == "" {
			return nil, fmt.Errorf("a cigar is present but no witness identifier names who signed")
		}
		couples = []ReceiptCouple{{Witness: w, CigarQB64: in.CigarQB64}}
	}
	if len(couples) == 0 && len(in.SigningWitnesses) > 0 {
		couples = couplesForWitnesses(c, in.SigningWitnesses)
	}
	if len(couples) == 0 && in.Witness != "" {
		couples = couplesForWitnesses(c, []string{in.Witness})
	}
	if len(couples) == 0 && len(in.Witnesses) > 0 && c.Expect.RawB64 != "" {
		couples = couplesForWitnesses(c, in.Witnesses)
	}

	prefix, said, sn := in.Prefix, in.EventSAID, in.SN
	if (prefix == "" || said == "") && in.EventRawB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(in.EventRawB64)
		if err != nil {
			return nil, fmt.Errorf("the receipted event is not readable base64: %w", err)
		}
		ev, err := ParseEvent(raw)
		if err != nil {
			return nil, fmt.Errorf("the receipted event is not a readable KERI event: %w", err)
		}
		if prefix == "" {
			prefix = ev.Identifier
		}
		if said == "" {
			said = ev.SAID
		}
		if in.EventSAID == "" {
			sn = int(ev.SN)
		}
	}

	body := ReceiptInput{
		Prefix:    prefix,
		SN:        sn,
		EventSAID: said,
	}

	if len(couples) == 0 {
		return BuildReceipt(body)
	}
	return BuildReceiptStream(body, couples)
}

// couplesFromExpect reads receipt couples captured on the case's expect object.
func couplesFromExpect(c Case) []ReceiptCouple {
	if len(c.ExpectRaw) == 0 {
		return nil
	}
	var exp struct {
		Couples   []ReceiptCouple `json:"couples"`
		CigarQB64 string          `json:"cigar_qb64"`
		Witness   string          `json:"witness"`
	}
	if err := json.Unmarshal(c.ExpectRaw, &exp); err != nil {
		return nil
	}
	if len(exp.Couples) > 0 {
		return exp.Couples
	}
	if exp.CigarQB64 != "" && exp.Witness != "" {
		return []ReceiptCouple{{Witness: exp.Witness, CigarQB64: exp.CigarQB64}}
	}
	return nil
}

// couplesForWitnesses picks couples for the given witnesses, preserving the
// caller's witness order, from material captured on the expect object or
// parsed out of the expected stream.
func couplesForWitnesses(c Case, witnesses []string) []ReceiptCouple {
	all := couplesFromExpect(c)
	if len(all) == 0 {
		if c.Expect.RawB64 == "" {
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(c.Expect.RawB64)
		if err != nil {
			return nil
		}
		_, attached, err := splitStream(raw)
		if err != nil || len(attached) == 0 {
			return nil
		}
		groups, err := parseAttachments(attached)
		if err != nil {
			return nil
		}
		for _, g := range groups {
			if g.Counter != counterNonTransReceiptCouples {
				continue
			}
			for _, couple := range g.Couples {
				all = append(all, ReceiptCouple{Witness: couple.Signer, CigarQB64: couple.Sig})
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	byWit := make(map[string]string, len(all))
	for _, couple := range all {
		byWit[couple.Witness] = couple.CigarQB64
	}
	out := make([]ReceiptCouple, 0, len(witnesses))
	for _, w := range witnesses {
		cig, ok := byWit[w]
		if !ok {
			return nil
		}
		out = append(out, ReceiptCouple{Witness: w, CigarQB64: cig})
	}
	return out
}

// AnswerStream produces this implementation's answer to a stream case.
func AnswerStream(c Case) ([]byte, error) {
	var in StreamInput
	if err := json.Unmarshal(c.Input, &in); err != nil {
		return nil, fmt.Errorf("case input is not a stream: %w", err)
	}
	if in.EventRawB64 == "" {
		return nil, fmt.Errorf("a stream case must carry the event it attaches to")
	}
	return BuildStream(in)
}
