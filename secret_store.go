package keri

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Storing secrets this package does not understand.
//
// A KeyStore generates and returns Ed25519 signers, which is all KERI itself
// needs. Systems built on KERI need more: a hybrid post-quantum identity holds
// ML-DSA and ML-KEM secrets alongside the classical ones, and those have to
// survive a restart exactly as the classical ones do.
//
// The wrong answer is for those systems to build their own encrypted store. Two
// stores means two encryption schemes, two sets of file permissions, two backup
// stories and two chances to get any of it wrong — and the second one is
// invariably written in a hurry by someone who needed somewhere to put a key.
//
// The other wrong answer is for this package to learn about post-quantum
// algorithms. It is a KERI implementation, offered as a conformant one; a
// proprietary or experimental cipher suite inside it makes it less useful to
// everyone who wanted the standard thing, and drags a large cryptography
// dependency into every consumer that never asked for it.
//
// So this stores BYTES under a name, with the same encryption, the same refusal
// to overwrite, and the same permissions as a key. What the bytes mean is the
// caller's business.

// SecretStore keeps arbitrary secret material.
//
// Implemented by the stores in this package. A caller holding secrets this
// package has no opinion about — post-quantum seeds, agreement keys, anything
// else — persists them here rather than inventing a second place.
type SecretStore interface {
	// PutSecret stores bytes under a name, refusing to replace an existing one.
	//
	// The refusal is deliberate and matches key storage: overwriting a secret
	// an identity has already committed to is unrecoverable, and a store that
	// allowed it would make that mistake silent.
	PutSecret(name string, secret []byte) error
	// Secret returns bytes stored earlier.
	Secret(name string) ([]byte, error)
}

// storedSecret is a secret on disk. Deliberately a different shape from
// storedKey, so a secret cannot be read back as a signing key by a caller that
// asked for the wrong thing.
type storedSecret struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Nonce   string `json:"nonce"`
	Sealed  string `json:"sealed"`
}

const secretKind = "secret"

// PutSecret stores bytes under a name, encrypted like everything else here.
func (f *FileKeyStore) PutSecret(name string, secret []byte) error {
	if name == "" {
		return fmt.Errorf("a secret needs a name to be found by later")
	}
	if len(secret) == 0 {
		return fmt.Errorf("refusing to store an empty secret under %q; an empty value "+
			"reads back as a valid secret and is not one", name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	nonce := make([]byte, f.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("could not read randomness for a nonce: %w", err)
	}
	// The name is authenticated, so a file cannot be moved to another name
	// without decryption failing — the same protection keys get.
	sealed := f.aead.Seal(nil, nonce, secret, []byte(name))

	body, err := json.Marshal(storedSecret{
		Version: keyFileVersion,
		Kind:    secretKind,
		Name:    name,
		Nonce:   base64.RawURLEncoding.EncodeToString(nonce),
		Sealed:  base64.RawURLEncoding.EncodeToString(sealed),
	})
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(f.fileName(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("something is already stored under %q; refusing to replace "+
				"it, because whatever committed to it could not be recovered", name)
		}
		return fmt.Errorf("could not write the secret %q: %w", name, err)
	}
	if _, err := fh.Write(body); err != nil {
		fh.Close()
		return fmt.Errorf("could not write the secret %q: %w", name, err)
	}
	// Sync before reporting success, for the reason keys are synced: a secret
	// reported as stored and lost to a crash is the unrecoverable case.
	if err := fh.Sync(); err != nil {
		fh.Close()
		return fmt.Errorf("could not flush the secret %q to disk: %w", name, err)
	}
	return fh.Close()
}

// Secret returns bytes stored earlier.
func (f *FileKeyStore) Secret(name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	body, err := os.ReadFile(f.fileName(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no secret named %q is held", name)
		}
		return nil, fmt.Errorf("could not read the secret %q: %w", name, err)
	}
	var record storedSecret
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, fmt.Errorf("the file for %q is not readable: %w", name, err)
	}
	if record.Kind != secretKind {
		// Almost certainly a signing key. Reading one back as opaque bytes
		// would hand a caller private key material it did not ask for.
		return nil, fmt.Errorf("%q holds a signing key, not a secret; read it with "+
			"Signer", name)
	}
	if record.Version != keyFileVersion {
		return nil, fmt.Errorf("the file for %q is version %d and this build understands "+
			"version %d", name, record.Version, keyFileVersion)
	}
	if record.Name != name {
		return nil, fmt.Errorf("the file found for %q says it is %q; the store has been "+
			"tampered with or copied from elsewhere", name, record.Name)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(record.Nonce)
	if err != nil {
		return nil, fmt.Errorf("the file for %q has an unreadable nonce: %w", name, err)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(record.Sealed)
	if err != nil {
		return nil, fmt.Errorf("the file for %q is unreadable: %w", name, err)
	}
	secret, err := f.aead.Open(nil, nonce, sealed, []byte(name))
	if err != nil {
		return nil, fmt.Errorf("the secret %q could not be decrypted; either the master "+
			"key is wrong or the file has been altered: %w", name, err)
	}
	return secret, nil
}

// PutSecret stores bytes in memory. Lost when the process ends, with the same
// consequence as a key stored here: whatever committed to it cannot be
// recovered.
func (m *MemoryKeyStore) PutSecret(name string, secret []byte) error {
	if name == "" {
		return fmt.Errorf("a secret needs a name to be found by later")
	}
	if len(secret) == 0 {
		return fmt.Errorf("refusing to store an empty secret under %q", name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.secrets == nil {
		m.secrets = map[string][]byte{}
	}
	if _, exists := m.secrets[name]; exists {
		return fmt.Errorf("something is already stored under %q; refusing to replace it", name)
	}
	if _, exists := m.signers[name]; exists {
		return fmt.Errorf("%q is already a signing key", name)
	}
	m.secrets[name] = append([]byte(nil), secret...)
	return nil
}

// Secret returns bytes stored earlier.
func (m *MemoryKeyStore) Secret(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[name]
	if !ok {
		if _, isKey := m.signers[name]; isKey {
			return nil, fmt.Errorf("%q holds a signing key, not a secret; read it with "+
				"Signer", name)
		}
		return nil, fmt.Errorf("no secret named %q is held", name)
	}
	return append([]byte(nil), s...), nil
}
