package main

import (
	"bytes"
	"encoding/json"

	keri "github.com/grapeid/keri-go"
)

// The rotation shapes whose authority turns on WHICH keys signed: partial
// rotations, dual-index signatures, augmented rotations, and the nested
// weighted thresholds of identities with several owners. Each is built here
// and judged by keripy; keri-go's own verdict on the same log travels with the
// case, so the judge can say whether the two agree as well as whether keripy
// accepted.
//
// Refusal cases are expected to be refused. keripy does not refuse a rotation
// whose signatures fall short outright: it holds it in escrow waiting for
// more, so it never becomes the identity's latest event. That is what the
// judge observes.

// identity is a founded identity whose next rotation is being tested.
type identity struct {
	icp []byte // signed inception message
	ev  *keri.Event
}

// found incepts an identity and records the inception as its own case, so a
// rotation case has its predecessor in keripy's database.
func found(label string, keys []keri.Signer, kt string, nexts []string, nt string) identity {
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: pubs(keys), Isith: json.RawMessage(kt),
		NextDigests: nexts, Nsith: json.RawMessage(nt),
	})
	must(err)
	signed, err := keri.SignEvent(raw, keys...)
	must(err)
	ev, err := keri.ParseEvent(raw)
	must(err)
	cases = append(cases, kase{
		Label: "icp/" + label, Kind: "kel", Why: "founds the identity the next case rotates",
		Event: b64(signed.Event), Msg: b64(signed.Message),
		KeriGo: kerigoVerdict([][]byte{signed.Message}),
	})
	return identity{icp: signed.Message, ev: ev}
}

// rotate builds a rotation of id, signs it at the stated places, and records it
// with the verdict expected of both implementations.
func rotate(id identity, label, why, expect string, keys []string, kt string,
	nexts []string, nt string, signers ...keri.PlacedSigner) {

	raw, err := keri.BuildRotation(keri.RotationInput{
		Prefix: id.ev.Identifier, PriorSAID: id.ev.SAID, SN: 1,
		Keys: keys, Isith: json.RawMessage(kt),
		NextDigests: nexts, Nsith: json.RawMessage(nt),
	})
	must(err)
	signed, err := keri.SignEventAt(raw, signers...)
	must(err)
	cases = append(cases, kase{
		Label: "rot/" + label, Kind: "kel", Why: why, Expect: expect,
		Event: b64(signed.Event), Msg: b64(signed.Message),
		KeriGo: kerigoVerdict([][]byte{id.icp, signed.Message}),
	})
}

// rotateWithJunk is rotate, with one more signature appended that does not
// verify: made by junkBy, but claiming the place of the key at junkAt.
func rotateWithJunk(id identity, label, why, expect string, keys []string, kt string,
	nexts []string, nt string, junkBy keri.Signer, junkAt int, signers ...keri.PlacedSigner) {

	raw, err := keri.BuildRotation(keri.RotationInput{
		Prefix: id.ev.Identifier, PriorSAID: id.ev.SAID, SN: 1,
		Keys: keys, Isith: json.RawMessage(kt),
		NextDigests: nexts, Nsith: json.RawMessage(nt),
	})
	must(err)
	var sigs []string
	for _, p := range signers {
		sig, err := p.Signer.Sign(raw)
		must(err)
		q, err := keri.EncodeIndexedSignature(sig, p.At)
		must(err)
		sigs = append(sigs, q)
	}
	junk, err := junkBy.Sign(raw)
	must(err)
	q, err := keri.EncodeIndexedSignature(junk, keri.SamePlace(junkAt))
	must(err)
	attachment, err := keri.AttachControllerSigs(append(sigs, q))
	must(err)
	msg := append(append([]byte{}, raw...), attachment...)
	cases = append(cases, kase{
		Label: "rot/" + label, Kind: "kel", Why: why, Expect: expect,
		Event: b64(raw), Msg: b64(msg),
		KeriGo: kerigoVerdict([][]byte{id.icp, msg}),
	})
}

func kerigoVerdict(log [][]byte) string {
	if _, err := keri.ValidateSignedKEL(log); err != nil {
		return "refused: " + err.Error()
	}
	return "accepted"
}

func pubs(ss []keri.Signer) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = pub(s)
	}
	return out
}

func digests(ss ...keri.Signer) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = digestOf(s)
	}
	return out
}

func at(s keri.Signer, index, ondex int) keri.PlacedSigner {
	return keri.PlacedSigner{Signer: s, At: keri.SignaturePlace{Index: index, Ondex: ondex}}
}

func currentOnly(s keri.Signer, index int) keri.PlacedSigner {
	return keri.PlacedSigner{Signer: s, At: keri.SignaturePlace{Index: index, CurrentOnly: true}}
}

// fresh hands out distinct key material. A single-key identifier IS its key,
// so two scenarios sharing a key would be one identity. The seeds are counted
// rather than tagged so they never meet the repeated-byte seeds main.go uses.
var freshCount int

func fresh() keri.Signer {
	freshCount++
	seed := bytes.Repeat([]byte{0xa5}, 32)
	seed[0], seed[1] = byte(freshCount), byte(freshCount>>8)
	s, err := keri.NewSoftwareSigner(seed, true)
	must(err)
	return s
}

func emitRotationShapes() {
	const accepted, refused = "", "refused"

	// ---- one owner: partial rotation with a dual-index signature ----------
	{
		owner, other, revealed, after := fresh(), fresh(), fresh(), fresh()
		// Commit [other, revealed], nt = 1. The rotation reveals the second
		// commitment alone, at k[0]: index 0, prior place 1, code 2A.
		id := found("partial-dual-index", []keri.Signer{owner}, `"1"`,
			digests(other, revealed), `"1"`)
		rotate(id, "partial-dual-index",
			"a partial rotation revealing n[1] at k[0], signed with index 0 and prior place 1",
			accepted, pubs([]keri.Signer{revealed}), `"1"`, digests(after), `"1"`,
			at(revealed, 0, 1))
	}
	{
		owner, other, revealed, after := fresh(), fresh(), fresh(), fresh()
		id := found("wrong-prior-place", []keri.Signer{owner}, `"1"`,
			digests(other, revealed), `"1"`)
		rotate(id, "wrong-prior-place",
			"the same reveal signed with prior place 0, which this key does not open",
			refused, pubs([]keri.Signer{revealed}), `"1"`, digests(after), `"1"`,
			at(revealed, 0, 0))
	}
	{
		owner, c, d, after := fresh(), fresh(), fresh(), fresh()
		// Both committed keys listed, kt = 1, nt = 2, and only one signs: the
		// listed keys would meet nt, the signing keys do not.
		id := found("too-few-exposed", []keri.Signer{owner}, `"1"`, digests(c, d), `"2"`)
		rotate(id, "too-few-exposed",
			"two committed keys listed under a prior nt of 2, and only one of them signs",
			refused, pubs([]keri.Signer{c, d}), `"1"`, digests(after), `"1"`,
			at(c, 0, 0))
	}

	// ---- augmented rotation -----------------------------------------------
	{
		owner, c, added, after := fresh(), fresh(), fresh(), fresh()
		id := found("augmented", []keri.Signer{owner}, `"1"`, digests(c), `"1"`)
		rotate(id, "augmented",
			"a rotation adding a key the inception never committed to; it signs "+
				"current-only and counts toward kt = 2 only",
			accepted, pubs([]keri.Signer{c, added}), `"2"`, digests(after), `"1"`,
			at(c, 0, 0), currentOnly(added, 1))
	}
	{
		owner, c, added, after := fresh(), fresh(), fresh(), fresh()
		id := found("added-key-alone", []keri.Signer{owner}, `"1"`, digests(c), `"1"`)
		rotate(id, "added-key-alone",
			"an augmented rotation signed by the added key alone, which opens nothing",
			refused, pubs([]keri.Signer{c, added}), `"1"`, digests(after), `"1"`,
			at(added, 1, 1))
	}

	// ---- a signature that does not verify -------------------------------
	//
	// Dropped and the rest judged, by both. It never counts: under kt = 2 it
	// would have been the second signature. keriox refuses any event carrying
	// such a signature, so these are not put to it.
	firstJunk := len(cases)
	{
		owner, c, d, after := fresh(), fresh(), fresh(), fresh()
		id := found("junk-signature", []keri.Signer{owner}, `"1"`, digests(c, d), `"1"`)
		rotateWithJunk(id, "junk-signature",
			"a valid rotation with a signature appended that does not verify",
			accepted, pubs([]keri.Signer{c, d}), `"1"`, digests(after), `"1"`,
			owner, 1, at(c, 0, 0))
	}
	{
		owner, c, d, after := fresh(), fresh(), fresh(), fresh()
		id := found("junk-signature-counted", []keri.Signer{owner}, `"1"`, digests(c, d), `"1"`)
		rotateWithJunk(id, "junk-signature-counted",
			"kt = 2 met only if the signature that does not verify were counted",
			refused, pubs([]keri.Signer{c, d}), `"2"`, digests(after), `"1"`,
			owner, 1, at(c, 0, 0))
	}
	for i := firstJunk; i < len(cases); i++ {
		if cases[i].Label != "icp/junk-signature" && cases[i].Label != "icp/junk-signature-counted" {
			cases[i].KerioxSkip = "keriox refuses an event carrying a signature that does " +
				"not verify, where keripy and keri-go drop it"
		}
	}

	// ---- two owners, both must act ----------------------------------------
	// Owner i holds k[i] and commits n[2i] (first) and n[2i+1]
	// (second). One clause per owner, each met by either of that owner's keys.
	const twoStageOne = `[["1","1"],["1","1"]]`
	const twoStageTwo = `[["1/2","1/2"],["1/2","1/2"]]`
	twoOwners := func(label string) (identity, [4]keri.Signer) {
		o0, o1 := fresh(), fresh()
		n := [4]keri.Signer{fresh(), fresh(), fresh(), fresh()}
		return found(label, []keri.Signer{o0, o1}, `"2"`, digests(n[:]...), twoStageOne), n
	}
	{
		id, n := twoOwners("two-owners")
		after := [4]keri.Signer{fresh(), fresh(), fresh(), fresh()}
		rotate(id, "two-owners",
			"both owners reveal their first key; owner 1 sits at k[1] and opens n[2]",
			accepted, pubs([]keri.Signer{n[0], n[2]}), `"2"`, digests(after[:]...), twoStageOne,
			at(n[0], 0, 0), at(n[2], 1, 2))
	}
	{
		id, n := twoOwners("two-owners-one-acts")
		after := [4]keri.Signer{fresh(), fresh(), fresh(), fresh()}
		rotate(id, "two-owners-one-acts",
			"owner 0 reveals both of their keys and owner 1 nothing; owner 1's clause is unmet",
			refused, pubs([]keri.Signer{n[0], n[1]}), `"1"`, digests(after[:]...), twoStageOne,
			at(n[0], 0, 0), at(n[1], 1, 1))
	}
	{
		id, n := twoOwners("two-owners-stage-two")
		after := [4]keri.Signer{fresh(), fresh(), fresh(), fresh()}
		rotate(id, "two-owners-stage-two",
			"both owners reveal both keys at their committed places, under weighted kt and nt",
			accepted, pubs(n[:]), twoStageTwo, digests(after[:]...), twoStageTwo,
			at(n[0], 0, 0), at(n[1], 1, 1), at(n[2], 2, 2), at(n[3], 3, 3))
	}

	// ---- three owners, any two --------------------------------------------
	//
	// keriox does not read nested weighted thresholds, so these cases are not
	// put to it; nothing here claims it does. keripy judges them.
	firstNested := len(cases)
	// Each owner is a nested set carrying weight 1/2, met by either of that
	// owner's two commitments: so any key of any two owners.
	const threeStageOne = `[{"1/2":["1","1"]},{"1/2":["1","1"]},{"1/2":["1","1"]}]`
	const threeStageTwo = `[{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]},{"1/2":["1/2","1/2"]}]`
	threeOwners := func(label string) (identity, [6]keri.Signer) {
		o := []keri.Signer{fresh(), fresh(), fresh()}
		var n [6]keri.Signer
		for i := range n {
			n[i] = fresh()
		}
		return found(label, o, `"2"`, digests(n[:]...), threeStageOne), n
	}
	afterSix := func() []string {
		var a [6]keri.Signer
		for i := range a {
			a[i] = fresh()
		}
		return digests(a[:]...)
	}
	{
		id, n := threeOwners("three-owners")
		rotate(id, "three-owners",
			"owners 0 and 2 reveal their first keys; owner 2 sits at k[1] and opens n[4]",
			accepted, pubs([]keri.Signer{n[0], n[4]}), `"2"`, afterSix(), threeStageOne,
			at(n[0], 0, 0), at(n[4], 1, 4))
	}
	{
		id, n := threeOwners("three-owners-second-key")
		rotate(id, "three-owners-second-key",
			"owner 0's first key with owner 2's second key, opening n[0] and n[5]",
			accepted, pubs([]keri.Signer{n[0], n[5]}), `"2"`, afterSix(), threeStageOne,
			at(n[0], 0, 0), at(n[5], 1, 5))
	}
	{
		id, n := threeOwners("three-owners-one-acts")
		rotate(id, "three-owners-one-acts",
			"owner 0 reveals both of their keys and nobody else acts; one owner is half",
			refused, pubs([]keri.Signer{n[0], n[1]}), `"2"`, afterSix(), threeStageOne,
			at(n[0], 0, 0), at(n[1], 1, 1))
	}
	{
		id, n := threeOwners("three-owners-stage-two")
		rotate(id, "three-owners-stage-two",
			"owners 0 and 2 reveal both keys each at their committed places, under nested kt and nt",
			accepted, pubs(n[:]), threeStageTwo, afterSix(), threeStageTwo,
			at(n[0], 0, 0), at(n[1], 1, 1), at(n[4], 4, 4), at(n[5], 5, 5))
	}
	for i := firstNested; i < len(cases); i++ {
		cases[i].KerioxSkip = "keriox does not read nested weighted thresholds"
	}
}
