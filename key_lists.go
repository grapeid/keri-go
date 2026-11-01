package keri

import (
	"crypto/ed25519"
	"fmt"
)

// One key, one vote.
//
// A threshold over a key list is "M of the N keys", and a threshold over a
// list of next-key digests is "M of the N committed keys". Either list naming
// one key twice turns one key into two votes: an inception with k=[a,a] and
// kt=2 is signed by a alone, and an inception with n=[H(c),H(c)] and nt=2 is
// taken over by whoever holds c alone. Counting each signature once does not
// help, because the two entries are two places, and each is opened honestly.
//
// So the list itself is refused. It is the same rule for the builders, which
// must never emit such an event, and for the validator, which must never
// accept one somebody else emitted; one function serves both, so the two cannot
// disagree about what a repeat is.

// noRepeatedKeysOrDigests refuses a signing key list that names one key twice,
// or a next-key digest list that names one digest twice. Builders return its
// error; checkKeyLists reports it as a fault.
func noRepeatedKeysOrDigests(keys, nextDigests []string) error {
	if err := noDuplicates(keys, "signing key"); err != nil {
		return err
	}
	return noDuplicates(nextDigests, "next-key digest")
}

// noDuplicates refuses a list in which two entries stand for the same value.
//
// Entries are compared by the key or digest they decode to, not by their text,
// so a key written once as a transferable key (D) and once as a
// non-transferable one (B) is still one key. An entry this package cannot
// decode is compared by its text: it can be counted by nothing here, so a
// spelling difference cannot become a second vote.
func noDuplicates(values []string, what string) error {
	seen := make(map[string]string, len(values))
	for _, v := range values {
		id := listEntryValue(v)
		if first, dup := seen[id]; dup {
			if first == v {
				return fmt.Errorf("the same %s is listed twice (%s), which would let "+
					"one key count as two", what, v)
			}
			return fmt.Errorf("the same %s is listed twice (%s and %s), which would "+
				"let one key count as two", what, first, v)
		}
		seen[id] = v
	}
	return nil
}

// listEntryValue is the value a key or digest list entry stands for, as a map
// key: two entries are the same key, or the same digest, exactly when their
// values are equal.
//
// An Ed25519 key is the same key under either code, so both decode to "key:"
// plus its bytes. A Blake3-256 digest decodes to "E" plus its bytes. Anything
// else stays as its text, under a prefix no decoded value can take.
func listEntryValue(qb64 string) string {
	for _, code := range []string{CodeEd25519, CodeEd25519N} {
		if raw, err := MatterRaw(code, qb64, ed25519.PublicKeySize); err == nil {
			return "key:" + string(raw)
		}
	}
	if raw, err := MatterRaw(CodeBlake3_256, qb64, 32); err == nil {
		return CodeBlake3_256 + ":" + string(raw)
	}
	return "text:" + qb64
}

// checkKeyLists is noRepeatedKeysOrDigests as a validation rule, applied to
// every establishment event: an inception, a rotation, and their delegated
// forms. An interaction carries no key lists.
func checkKeyLists(fs *faults, ev *Event) {
	if !ev.Establishment() {
		return
	}
	if err := noRepeatedKeysOrDigests(ev.Keys, ev.NextDigest); err != nil {
		fs.add(FaultKeyListInvalid, "%v", err)
	}
}
