// Command interop emits everything this package can build, for keripy to judge.
//
// The conformance suite proves one direction: given keripy's inputs, this
// package reproduces keripy's bytes. That is a string comparison. This asks the
// stricter question — does keripy ACCEPT what we produce? — by running the
// reference implementation's own validator over our output.
//
// Everything goes through the package's public API, key derivation and signing
// included. An earlier version hand-rolled the encoding here, which meant it
// proved this file correct rather than the library.
//
// Writes a stream of cases to stdout. interop/verify_interop.py feeds each to
// the part of keripy that judges its kind.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	keri "github.com/grapeid/keri-go"
)

// A case is one thing for keripy to judge. Kind says which validator applies:
// key events go to a Kevery, transaction events to a Tevery, credentials are
// checked as documents.
type kase struct {
	Label   string   `json:"label"`
	Kind    string   `json:"kind"`
	Why     string   `json:"why"`
	Event   string   `json:"event_b64,omitempty"`
	Msg     string   `json:"message_b64,omitempty"`
	Extra   []string `json:"extra_b64,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
	Skipped string   `json:"skipped,omitempty"`
}

var cases []kase

func signerFor(tag byte, transferable bool) keri.Signer {
	s, err := keri.NewSoftwareSigner(bytes.Repeat([]byte{tag}, 32), transferable)
	must(err)
	return s
}

func pub(s keri.Signer) string {
	p, err := s.PublicKey()
	must(err)
	return p
}

func digestOf(s keri.Signer) string {
	d, err := keri.NextDigest(pub(s))
	must(err)
	return d
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// emitKEL signs a key event and records it for the Kevery.
func emitKEL(label, why string, event []byte, signers ...keri.Signer) *keri.Event {
	signed, err := keri.SignEvent(event, signers...)
	must(err)
	ev, err := keri.ParseEvent(event)
	must(err)
	cases = append(cases, kase{
		Label: label, Kind: "kel", Why: why,
		Event: b64(signed.Event), Msg: b64(signed.Message),
	})
	return ev
}

func main() {
	a, b, c, d, e := signerFor('a', true), signerFor('b', true), signerFor('c', true),
		signerFor('d', true), signerFor('e', true)
	// Separate key material per scenario. A single-key identifier IS its key, so
	// two inceptions sharing a signer are two inceptions of the SAME identity —
	// which is duplicity, and correctly refused.
	wa, wb := signerFor('m', true), signerFor('n', true)
	da, db, dc, dd := signerFor('p', true), signerFor('q', true),
		signerFor('r', true), signerFor('s', true)
	w1, w2, w3 := signerFor('w', false), signerFor('x', false), signerFor('y', false)
	wits := []string{pub(w1), pub(w2), pub(w3)}

	// ---- plain key events -------------------------------------------------

	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(a)}, NextDigests: []string{digestOf(b)},
	})
	must(err)
	icpEv := emitKEL("icp/single-key", "the simplest identity there is", icp, a)

	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix: icpEv.Identifier, PriorSAID: icpEv.SAID, SN: 1,
		Data: []json.RawMessage{},
	})
	must(err)
	ixnEv := emitKEL("ixn/no-seals", "an interaction anchoring nothing", ixn, a)

	// An interaction carrying a seal — the shape a delegation approval and a
	// credential issuance both take.
	seal := json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`,
		icpEv.Identifier, icpEv.SAID))
	ixn2, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix: icpEv.Identifier, PriorSAID: ixnEv.SAID, SN: 2,
		Data: []json.RawMessage{seal},
	})
	must(err)
	ixn2Ev := emitKEL("ixn/with-seal", "an interaction anchoring a seal", ixn2, a)

	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, Keys: []string{pub(b)}, PriorSAID: ixn2Ev.SAID,
		SN: 3, NextDigests: []string{digestOf(c)},
	})
	must(err)
	emitKEL("rot/to-precommitted-key",
		"rotating to the key the inception committed to by digest", rot, b)

	// ---- thresholds -------------------------------------------------------

	multi, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(a), pub(c)}, Isith: json.RawMessage(`"2"`),
		NextDigests: []string{digestOf(d), digestOf(e)}, Nsith: json.RawMessage(`"2"`),
	})
	must(err)
	emitKEL("icp/two-of-two", "both keys must sign, so both indices must be right",
		multi, a, c)

	// A weighted threshold, where "enough" is a sum of fractions rather than a
	// count. Encoded differently and easy to get subtly wrong.
	weighted, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{pub(a), pub(c), pub(d)},
		Isith:       json.RawMessage(`["1/2","1/2","1/2"]`),
		NextDigests: []string{digestOf(b), digestOf(e)},
		Nsith:       json.RawMessage(`["1/2","1/2"]`),
	})
	must(err)
	emitKEL("icp/weighted-threshold", "two of three halves meet a threshold of one",
		weighted, a, c)

	// ---- witnessed events, and the receipts that make them acceptable ------

	// A witnessed inception is not accepted on its own: it waits for enough
	// witness receipts to meet the threshold it declares. So the receipts are
	// part of the same case, and this exercises the receipt builder against the
	// reference for the first time.
	wIcp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(wa)}, NextDigests: []string{digestOf(wb)},
		Witnesses: wits, Toad: intPtr(2),
	})
	must(err)
	wIcpEv, err := keri.ParseEvent(wIcp)
	must(err)
	wSigned, err := keri.SignEvent(wIcp, wa)
	must(err)

	var receipts []string
	for _, w := range []keri.Signer{w1, w2} {
		sig, err := w.Sign(wIcp)
		must(err)
		stream, err := keri.BuildReceiptStream(
			keri.ReceiptInput{Prefix: wIcpEv.Identifier, SN: 0, EventSAID: wIcpEv.SAID},
			[]keri.ReceiptCouple{{Witness: pub(w), CigarQB64: mustCigar(sig)}},
		)
		must(err)
		receipts = append(receipts, b64(stream))
	}
	cases = append(cases, kase{
		Label: "icp/witnessed+receipts", Kind: "kel", Why: "a witnessed inception is " +
			"held until enough witnesses have receipted it; these receipts are built " +
			"by this package",
		Event: b64(wSigned.Event), Msg: b64(wSigned.Message), Extra: receipts,
	})

	// ---- delegation -------------------------------------------------------

	// A delegated inception, plus the delegator's approval anchoring it.
	delegatorIcp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(da)}, NextDigests: []string{digestOf(db)},
	})
	must(err)
	delegatorEv := emitKEL("icp/delegator", "the identity that will delegate", delegatorIcp, da)

	dip, err := keri.BuildDelegatedInception(keri.DelegationInput{
		Keys: []string{pub(dc)}, NextDigests: []string{digestOf(dd)},
		Delegator: delegatorEv.Identifier,
	})
	must(err)
	dipEv, err := keri.ParseEvent(dip)
	must(err)
	dipSigned, err := keri.SignEvent(dip, dc)
	must(err)

	// The delegator approves by anchoring a seal naming the delegate, the
	// sequence number, and the digest.
	approvalSeal := json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`,
		dipEv.Identifier, dipEv.SAID))
	approval, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix: delegatorEv.Identifier, PriorSAID: delegatorEv.SAID, SN: 1,
		Data: []json.RawMessage{approvalSeal},
	})
	must(err)
	approvalSigned, err := keri.SignEvent(approval, da)
	must(err)
	cases = append(cases, kase{
		Label: "dip/with-delegator-approval", Kind: "delegation",
		Why:   "a delegated inception is only valid once its delegator anchors it",
		Event: b64(dipSigned.Event), Msg: b64(dipSigned.Message),
		Extra: []string{b64(approvalSigned.Message)},
	})

	// ---- credentials and their transaction events -------------------------

	emitCredentials(icpEv.Identifier)

	if err := json.NewEncoder(os.Stdout).Encode(cases); err != nil {
		must(err)
	}
}

// emitCredentials builds a registry, a credential and its issuance and
// revocation, so keripy can judge the ACDC side too.
func emitCredentials(issuer string) {
	registry, err := keri.BuildRegistryInception(keri.RegistryInput{
		Issuer: issuer,
		Nonce:  "0ADYvfKAeqRVAyc-Gu0Zc7SN",
	})
	if err != nil {
		cases = append(cases, kase{Label: "vcp/registry", Kind: "tel",
			Skipped: fmt.Sprintf("could not build a registry: %v", err)})
		return
	}
	cases = append(cases, kase{
		Label: "vcp/registry-inception", Kind: "tel",
		Why:   "a credential registry, which issuances are recorded against",
		Event: b64(registry), Issuer: issuer,
	})
}

func mustCigar(sig []byte) string {
	q, err := keri.MatterQB64(keri.CodeEd25519Sig, sig)
	must(err)
	return q
}

func intPtr(n int) *int { return &n }

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
