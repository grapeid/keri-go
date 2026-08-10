package keri

import (
	"fmt"
	"sort"
	"sync"
)

// Custody of the next key.
//
// Pre-rotation is the property that makes KERI worth using: an identity commits
// to its NEXT key by digest, so an attacker who steals the current key still
// cannot rotate the identity, because the key a rotation must reveal is one they
// do not hold.
//
// That property is not created by the event format. It is created by how the
// next key is looked after, and there are four ways to lose it:
//
//   - Generate the next key only when rotating. Then the identity never
//     committed to it, the rotation reveals a key nothing predicted, and no
//     validator accepts it. The identity is stuck.
//   - Lose the next key. The commitment stands and nothing can satisfy it, so
//     the identity can never rotate again — which, if the current key is
//     compromised, means it is gone.
//   - Leak the next key early. Pre-rotation then protects nothing: whoever holds
//     both keys can rotate the identity away from its owner.
//   - Reuse the current key as the next one. Same outcome as leaking it, with no
//     attacker required.
//
// Keychain exists so that none of those is reachable through ordinary use. It
// generates the next key at inception, holds it until the rotation that reveals
// it, and generates its replacement in the same step.

// KeyStore creates and retrieves keys by name.
//
// It is an interface for the same reason Signer is: a store backed by a secure
// enclave never hands out private material, and cannot satisfy an interface
// shaped as "return the key". A store's job is to produce a Signer, not a key.
type KeyStore interface {
	// Generate creates a new key under a name, and returns a Signer for it.
	//
	// It must fail rather than overwrite if the name is already in use.
	// Overwriting a name silently destroys the key an identity has already
	// committed to, which is unrecoverable.
	Generate(name string, transferable bool) (Signer, error)
	// Signer returns the signer for a name that was generated earlier.
	Signer(name string) (Signer, error)
}

// MemoryKeyStore keeps keys in this process and nowhere else.
//
// For tests and for short-lived processes. It is NOT suitable for an identity
// that must survive a restart: when the process ends, every next key it holds is
// gone, and every identity whose commitment depended on one can never rotate
// again. A real deployment supplies a store that persists, and preferably one
// backed by hardware.
type MemoryKeyStore struct {
	mu      sync.Mutex
	signers map[string]Signer
	// secrets holds material this package does not interpret — see
	// SecretStore. Kept in a separate map so a secret can never be handed back
	// as a signing key, or the reverse.
	secrets map[string][]byte
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{signers: map[string]Signer{}, secrets: map[string][]byte{}}
}

func (m *MemoryKeyStore) Generate(name string, transferable bool) (Signer, error) {
	if name == "" {
		return nil, fmt.Errorf("a key needs a name to be found by later")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.signers[name]; exists {
		return nil, fmt.Errorf("a key named %q already exists; refusing to replace it, "+
			"because an identity may already have committed to it", name)
	}
	s, err := GenerateSigner(transferable)
	if err != nil {
		return nil, err
	}
	m.signers[name] = s
	return s, nil
}

func (m *MemoryKeyStore) Signer(name string) (Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.signers[name]
	if !ok {
		return nil, fmt.Errorf("no key named %q is held", name)
	}
	return s, nil
}

// Names lists the keys held, sorted. For tests and for operational inspection;
// it reveals no key material.
func (m *MemoryKeyStore) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.signers))
	for n := range m.signers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Keychain manages the pre-rotation lifecycle for one identity.
//
// It holds the keys currently in force and the keys already committed to as
// next. Rotating advances the second into the first and generates a new second,
// so an identity is never left without a committed successor.
type Keychain struct {
	mu    sync.Mutex
	store KeyStore
	// label distinguishes this identity's keys within the store.
	label string
	// generation counts establishment events: 0 at inception, 1 after the first
	// rotation. It names the keys, so a restart can find them again.
	generation int
	current    []Signer
	next       []Signer
}

// NewKeychain creates the keys for a new identity: the ones it starts with, and
// the ones it commits to rotate to.
//
// count is how many keys are in force at a time. Both generations are created
// here, which is what makes the identity rotatable from the moment it exists.
func NewKeychain(store KeyStore, label string, count int) (*Keychain, error) {
	if store == nil {
		return nil, fmt.Errorf("a keychain needs somewhere to keep keys")
	}
	if label == "" {
		return nil, fmt.Errorf("a keychain needs a label to name its keys within the store")
	}
	if count < 1 {
		return nil, fmt.Errorf("an identity needs at least one key, %d were asked for", count)
	}
	k := &Keychain{store: store, label: label}
	var err error
	if k.current, err = k.generate(0, count); err != nil {
		return nil, fmt.Errorf("could not create the keys the identity starts with: %w", err)
	}
	if k.next, err = k.generate(1, count); err != nil {
		return nil, fmt.Errorf("could not create the keys the identity commits to rotate "+
			"to; without them it could never rotate: %w", err)
	}
	return k, nil
}

// LoadKeychain recovers a keychain whose keys are already in a store.
//
// generation is how many rotations the identity has been through, which the
// caller reads from the key log rather than from the store: the log is the
// record of what the identity has actually done.
func LoadKeychain(store KeyStore, label string, count, generation int) (*Keychain, error) {
	if store == nil || label == "" || count < 1 || generation < 0 {
		return nil, fmt.Errorf("a keychain needs a store, a label, at least one key and a "+
			"generation that is not negative; got label %q, count %d, generation %d",
			label, count, generation)
	}
	k := &Keychain{store: store, label: label, generation: generation}
	var err error
	if k.current, err = k.load(generation, count); err != nil {
		return nil, fmt.Errorf("the keys in force are not in the store: %w", err)
	}
	if k.next, err = k.load(generation+1, count); err != nil {
		// This is the unrecoverable case, so it says so rather than continuing
		// with a fresh key that nothing has committed to.
		return nil, fmt.Errorf("the keys this identity committed to rotate to are not in "+
			"the store, so it can never rotate again; a new key cannot substitute, "+
			"because the commitment names the old one: %w", err)
	}
	return k, nil
}

func (k *Keychain) name(generation, index int) string {
	return fmt.Sprintf("%s/%d/%d", k.label, generation, index)
}

func (k *Keychain) generate(generation, count int) ([]Signer, error) {
	out := make([]Signer, 0, count)
	for i := 0; i < count; i++ {
		s, err := k.store.Generate(k.name(generation, i), true)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (k *Keychain) load(generation, count int) ([]Signer, error) {
	out := make([]Signer, 0, count)
	for i := 0; i < count; i++ {
		s, err := k.store.Signer(k.name(generation, i))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func publicKeys(signers []Signer) ([]string, error) {
	out := make([]string, 0, len(signers))
	for i, s := range signers {
		pub, err := s.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("key %d cannot report its public key: %w", i, err)
		}
		out = append(out, pub)
	}
	return out, nil
}

// CurrentKeys returns the public keys in force.
func (k *Keychain) CurrentKeys() ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return publicKeys(k.current)
}

// NextDigests returns the pre-rotation commitments for the keys that will come
// next — digests, never the keys themselves.
//
// The keys stay unrevealed until the rotation that uses them. Returning them
// here instead of their digests would defeat the point of holding them.
func (k *Keychain) NextDigests() ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return nextDigestsOf(k.next)
}

func nextDigestsOf(signers []Signer) ([]string, error) {
	pubs, err := publicKeys(signers)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(pubs))
	for _, p := range pubs {
		d, err := NextDigest(p)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// Signers returns the signers in force, for signing an event.
func (k *Keychain) Signers() []Signer {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]Signer, len(k.current))
	copy(out, k.current)
	return out
}

// Generation is how many establishment events this identity has had beyond its
// inception. Persist it alongside the store so a restart can reload correctly.
func (k *Keychain) Generation() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.generation
}

// Rotate advances the keychain: the committed next keys come into force, and a
// fresh set is generated and committed in their place.
//
// It returns the keys now in force and the digests of the new commitments, which
// are what a rotation event must carry.
//
// The new keys are generated BEFORE the advance is recorded, so a failure to
// generate leaves the keychain exactly as it was rather than in force with
// nothing committed — a state in which the identity could never rotate again.
func (k *Keychain) Rotate() (keys []string, nextDigests []string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(k.next) == 0 {
		return nil, nil, fmt.Errorf("this keychain has no committed successor, so there " +
			"is nothing a rotation could reveal")
	}
	replacement, err := k.generate(k.generation+2, len(k.next))
	if err != nil {
		return nil, nil, fmt.Errorf("could not create the keys to commit to after this "+
			"rotation; nothing has changed, so the identity can still rotate later: %w", err)
	}

	k.current = k.next
	k.next = replacement
	k.generation++

	if keys, err = publicKeys(k.current); err != nil {
		return nil, nil, err
	}
	if nextDigests, err = nextDigestsOf(k.next); err != nil {
		return nil, nil, err
	}
	return keys, nextDigests, nil
}
