package keri

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
)

// Exchange messages — one identity saying something to another.
//
// An exchange message (`exn`) is KERI's own message for peer to peer traffic:
// it names who sends it (i), who it is for (rp), the message it follows (p),
// when it was made (dt), how to read it (r), and carries the content (a). Its
// identifier (d) is a digest of the message, so it cannot be altered, and it is
// signed by its sender, so it can be kept and shown to anybody. It is not part
// of a key event log: nothing here adds to any identity's history.
//
// The bytes are keripy's `exchanging.exchange` byte for byte (the field order
// v t d i rp p dt r q a e, no white space), and a keripy `Exchanger` accepts
// the signed form this package makes. exchange_test.go holds both to that with
// vectors keripy built, and interop/keripy_accepts_exchange.py asks keripy
// itself.
//
// WHO SIGNS. The signature that keripy accepts for a sender is one made by the
// key of the identifier in `i`. For a sender that cannot sign with its
// identity's own key log key at the moment it speaks, the sender's identifier
// is a NON-TRANSFERABLE one (an Ed25519 key that is its own identifier, code B)
// and the attached signature is a non-transferable couple: the identifier and
// the signature, which keripy checks with nothing else. What binds that
// identifier to an identity with a key log is the caller's business, and is
// not decided here.

const (
	ilkExchange = "exn"

	// maxExchangeSize bounds a message this package will read. The length is
	// declared in the message itself, and a reader that believed any declared
	// length could be made to read without end.
	maxExchangeSize = 1 << 20
)

// exnWire is an exchange message in the order the message carries it.
type exnWire struct {
	V  string          `json:"v"`
	T  string          `json:"t"`
	D  string          `json:"d"`
	I  string          `json:"i"`
	RP string          `json:"rp"`
	P  string          `json:"p"`
	DT string          `json:"dt"`
	R  string          `json:"r"`
	Q  json.RawMessage `json:"q"`
	A  json.RawMessage `json:"a"`
	E  json.RawMessage `json:"e"`
}

// ExchangeInput is what the sender of an exchange message states.
type ExchangeInput struct {
	// Sender is the identifier that signs it, as CESR.
	Sender string
	// Recipient is who it is for: an identifier, in the CESR form, or empty
	// for a message to nobody in particular. A message with a recipient has it
	// named in its content too (`a.i`), as keripy writes it.
	Recipient string
	// Prior is the identifier (d) of the exchange message this one follows, or
	// empty when it follows none.
	Prior string
	// DT is when it was made, as keripy writes a date: ISO 8601 with
	// microseconds and an offset, for example 2026-11-14T12:00:00.000000+00:00.
	DT string
	// Route says how to read the content.
	Route string
	// Modifiers is `q`, what a request carries beside its content: a JSON
	// object, or nil for an empty one.
	Modifiers json.RawMessage
	// Data is the content: a JSON object already in the order it is to take.
	// It follows `i` (the recipient) in `a`, and may not itself carry one.
	Data json.RawMessage
}

// BuildExchange assembles an exchange message and its identifier.
func BuildExchange(in ExchangeInput) ([]byte, error) {
	if in.Sender == "" {
		return nil, fmt.Errorf("an exchange message must say who sends it")
	}
	if in.Route == "" {
		return nil, fmt.Errorf("an exchange message must carry a route, or a recipient cannot know how to read it")
	}
	if in.DT == "" {
		return nil, fmt.Errorf("an exchange message must say when it was made")
	}
	q := in.Modifiers
	if len(q) == 0 {
		q = json.RawMessage(`{}`)
	}
	if !isJSONObject(q) {
		return nil, fmt.Errorf("the modifiers of an exchange message are a JSON object")
	}
	if len(in.Data) != 0 && !isJSONObject(in.Data) {
		return nil, fmt.Errorf("the content of an exchange message is a JSON object")
	}
	if strings.ContainsAny(in.Sender+in.Recipient+in.Prior+in.DT+in.Route+string(in.Modifiers)+string(in.Data), lineSeparators) {
		return nil, fmt.Errorf("an exchange message does not carry U+2028 or U+2029: Go writes them as escapes and keripy as themselves, so the bytes would not be keripy's")
	}
	a, err := exchangeAttributes(in.Recipient, in.Data)
	if err != nil {
		return nil, err
	}
	w := exnWire{
		V:  placeholderVersionString(ProtocolKERI, V1),
		T:  ilkExchange,
		D:  saidDummy(),
		I:  in.Sender,
		RP: in.Recipient,
		P:  in.Prior,
		DT: in.DT,
		R:  in.Route,
		Q:  q,
		A:  a,
		E:  json.RawMessage(`{}`),
	}
	dummy, err := serializeVersioned(w, ProtocolKERI, V1)
	if err != nil {
		return nil, err
	}
	said, err := saidOf(dummy)
	if err != nil {
		return nil, err
	}
	w.D = said
	return serializeVersioned(w, ProtocolKERI, V1)
}

// exchangeAttributes writes `a`: the recipient first when there is one, then
// the content, as keripy does (`attrs['i'] = recipient; attrs |= payload`).
func exchangeAttributes(recipient string, data json.RawMessage) (json.RawMessage, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	n := 0
	if recipient != "" {
		ri, err := marshalCanonical(recipient)
		if err != nil {
			return nil, err
		}
		b.WriteString(`"i":`)
		b.Write(bytes.TrimSpace(ri))
		n++
	}
	if len(data) != 0 {
		inner := bytes.TrimSpace(data)
		inner = bytes.TrimSpace(inner[1 : len(inner)-1])
		if len(inner) != 0 {
			var seen map[string]json.RawMessage
			if err := json.Unmarshal(data, &seen); err != nil {
				return nil, err
			}
			if _, dup := seen["i"]; dup && recipient != "" {
				return nil, fmt.Errorf("the content of an exchange message does not carry its own recipient (i): the recipient is named for it")
			}
			if n > 0 {
				b.WriteByte(',')
			}
			b.Write(inner)
			n++
		}
	}
	b.WriteByte('}')
	var compact bytes.Buffer
	if err := json.Compact(&compact, b.Bytes()); err != nil {
		return nil, fmt.Errorf("the content of an exchange message is not JSON: %w", err)
	}
	return compact.Bytes(), nil
}

// lineSeparators are the two characters Go's JSON encoder writes as escapes and
// keripy writes as themselves. A message holding either would be bytes keripy
// does not produce, so it is refused rather than built differently.
const lineSeparators = "\u2028\u2029"

func isJSONObject(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) >= 2 && t[0] == '{' && t[len(t)-1] == '}' && json.Valid(t)
}

// Exchange is what a reader gets out of an exchange message.
type Exchange struct {
	SAID      string
	Sender    string
	Recipient string
	Prior     string
	DT        string
	Route     string
	Modifiers json.RawMessage
	// Data is `a` exactly as carried: the recipient (when there is one) and
	// then the content.
	Data json.RawMessage
	// Raw is the message as read, which is what its signature covers.
	Raw []byte
}

// VerifyExchange checks that a message is one exchange message in its one
// form, and that its identifier is the digest of it, and returns what it says.
//
// It does not check a signature or know who the sender is: whoever vouches for
// the sender does that (VerifyExchangeSigned).
//
// The form is checked by building it again. A message read here has exactly the
// fields keripy writes, in its order, with no white space and nothing after
// it, so there is one spelling of every message and a copy that spells it
// otherwise is refused, not read as equal.
func VerifyExchange(raw []byte) (*Exchange, error) {
	if len(raw) == 0 || len(raw) > maxExchangeSize {
		return nil, fmt.Errorf("this is not an exchange message: it is %d bytes", len(raw))
	}
	if bytes.ContainsAny(raw, lineSeparators) {
		return nil, fmt.Errorf("an exchange message does not carry U+2028 or U+2029, which keripy and this package would spell differently")
	}
	var w exnWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("this is not a readable exchange message: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("an exchange message has nothing after it")
	}
	if w.T != ilkExchange {
		return nil, fmt.Errorf("this is a %q message, not an exchange message", w.T)
	}
	if w.D == "" || w.I == "" || w.R == "" || w.DT == "" {
		return nil, fmt.Errorf("an exchange message carries an identifier, a sender, a route and a date")
	}
	if len(w.Q) == 0 || len(w.A) == 0 || len(w.E) == 0 {
		return nil, fmt.Errorf("an exchange message carries q, a and e")
	}
	again := w
	again.D = saidDummy()
	dummy, err := serializeVersioned(again, ProtocolKERI, V1)
	if err != nil {
		return nil, err
	}
	said, err := saidOf(dummy)
	if err != nil {
		return nil, err
	}
	if said != w.D {
		return nil, fmt.Errorf("the exchange message does not match its own identifier, so it has been "+
			"altered since it was made: it says %s and computes to %s", w.D, said)
	}
	again.D = w.D
	canon, err := serializeVersioned(again, ProtocolKERI, V1)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canon, raw) {
		return nil, fmt.Errorf("the exchange message is not in its one form (field order, white space or a size that is not its own)")
	}
	recipient := w.RP
	if recipient != "" {
		var a map[string]json.RawMessage
		if err := json.Unmarshal(w.A, &a); err != nil {
			return nil, fmt.Errorf("the content of the exchange message is not a JSON object: %w", err)
		}
		var named string
		if err := json.Unmarshal(a["i"], &named); err != nil || named != recipient {
			return nil, fmt.Errorf("an exchange message for a recipient names the same one in its content")
		}
	}
	return &Exchange{SAID: w.D, Sender: w.I, Recipient: w.RP, Prior: w.P, DT: w.DT,
		Route: w.R, Modifiers: w.Q, Data: w.A, Raw: raw}, nil
}

// SignExchange makes the signed form of an exchange message whose sender is a
// non-transferable identifier (the verifying key itself, code B): the message,
// then one non-transferable couple of the sender and its signature over the
// message, the form keripy's `Exchanger` reads.
func SignExchange(raw []byte, key ed25519.PrivateKey) ([]byte, error) {
	ex, err := VerifyExchange(raw)
	if err != nil {
		return nil, err
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("an exchange message is signed with an Ed25519 key")
	}
	sender, err := MatterQB64(CodeEd25519N, pub)
	if err != nil {
		return nil, err
	}
	if ex.Sender != sender {
		return nil, fmt.Errorf("the key does not belong to the message's sender, %s", ex.Sender)
	}
	cigar, err := MatterQB64(CodeEd25519Sig, ed25519.Sign(key, raw))
	if err != nil {
		return nil, err
	}
	att, err := AttachReceiptCouples([]ReceiptCouple{{Witness: sender, CigarQB64: cigar}})
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), raw...), att...), nil
}

// SignedExchange is a signed exchange message as read.
type SignedExchange struct {
	Exchange
	// Signature is the raw Ed25519 signature the sender made over Raw.
	Signature []byte
}

// VerifyExchangeSigned reads a signed exchange message whose sender is a
// non-transferable identifier and checks it, as keripy does: the message is in
// its one form and carries its own identifier, it has exactly one attachment,
// a non-transferable couple, and the couple is the sender's own key and a
// signature by it that holds over the message.
//
// A message whose sender is a transferable identifier, or that carries
// anything else attached, is refused: that is not the form this checks, and
// accepting part of what a message says is how the rest of it gets believed.
func VerifyExchangeSigned(stream []byte) (*SignedExchange, error) {
	if len(stream) > maxExchangeSize+1024 {
		return nil, fmt.Errorf("this is not a signed exchange message: it is too long")
	}
	event, attached, err := splitStream(stream)
	if err != nil {
		return nil, err
	}
	ex, err := VerifyExchange(event)
	if err != nil {
		return nil, err
	}
	groups, err := parseAttachments(attached)
	if err != nil {
		return nil, err
	}
	if len(groups) != 1 || groups[0].Counter != CounterNonTransReceiptCouples ||
		len(groups[0].Couples) != 1 || len(groups[0].Sigs) != 0 {
		return nil, fmt.Errorf("a signed exchange message carries one attachment: the sender's signature as a non-transferable couple")
	}
	c := groups[0].Couples[0]
	if !strings.HasPrefix(ex.Sender, CodeEd25519N) {
		return nil, fmt.Errorf("the sender of this message is not a non-transferable identifier, so its own key is not what signed it")
	}
	if c.Signer != ex.Sender {
		return nil, fmt.Errorf("the signature is not by the message's sender")
	}
	pub, err := MatterRaw(CodeEd25519N, ex.Sender, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("the sender is not an Ed25519 key: %w", err)
	}
	sig, err := MatterRaw(CodeEd25519Sig, c.Sig, ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("the signature is not an Ed25519 signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), ex.Raw, sig) {
		return nil, fmt.Errorf("the signature does not hold over the message")
	}
	return &SignedExchange{Exchange: *ex, Signature: sig}, nil
}
