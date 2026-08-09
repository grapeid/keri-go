package keri

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Keys that survive a restart.
//
// MemoryKeyStore loses everything when the process ends, which for a KERI
// identity is not an inconvenience: the key it committed to rotate to is gone,
// nothing else can satisfy that commitment, and the identity can never rotate
// again. If its current key is ever compromised after that, there is no
// recovery. So an identity that outlives a process needs its keys to as well.
//
// This stores each key in its own file, encrypted with AES-256-GCM under a key
// the caller supplies. Two decisions are worth stating because both prevent a
// specific attack:
//
//   - Files are created with O_EXCL, so "do not overwrite an existing key" is
//     enforced by the filesystem rather than by a check that could race. A
//     silent overwrite destroys a key an identity has already committed to.
//   - The key's NAME is authenticated along with the ciphertext. Without that,
//     anyone who could write to the directory could swap two key files and make
//     an identity sign with a key other than the one it believes it is using,
//     without breaking any signature or decryption.
//
// It is not the end state. The best available answer is a key that never leaves
// hardware, and the interfaces here are shaped so an enclave-backed store can
// replace this one without anything else changing.

const (
	// keyFileVersion is written into every file so a future format change can
	// be detected rather than misread as corruption.
	keyFileVersion = 1
	// masterKeyLen is the length of the key that protects the stored keys.
	masterKeyLen = 32
)

// FileKeyStore keeps keys on disk, encrypted under a master key.
type FileKeyStore struct {
	mu   sync.Mutex
	dir  string
	aead cipher.AEAD
}

// storedKey is what a key file holds. The seed is the ciphertext; nothing here
// is secret except through that.
type storedKey struct {
	Version      int    `json:"version"`
	Name         string `json:"name"`
	Transferable bool   `json:"transferable"`
	Nonce        string `json:"nonce"`
	Sealed       string `json:"sealed"`
}

// NewFileKeyStore opens or creates a store in dir, protected by masterKey.
//
// masterKey must be 32 bytes and is the caller's responsibility: everything in
// the directory is readable to whoever holds it. Where it comes from is a
// deliberate omission — a passphrase, a system keyring, or hardware are all
// reasonable and none of them belong in this package. DeriveMasterKey is
// provided for the passphrase case.
func NewFileKeyStore(dir string, masterKey []byte) (*FileKeyStore, error) {
	if len(masterKey) != masterKeyLen {
		return nil, fmt.Errorf("the master key must be %d bytes, this one is %d",
			masterKeyLen, len(masterKey))
	}
	if dir == "" {
		return nil, fmt.Errorf("a file key store needs a directory")
	}
	// 0700: keys are readable only by the user running this.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("could not create the key directory %s: %w", dir, err)
	}
	// MkdirAll is subject to the process umask, and does nothing at all when the
	// directory already exists — so requesting 0700 above does not mean the
	// directory has it. Set it explicitly. Without this the directory is
	// typically created 0755 and anyone on the machine can list which
	// identities exist and when their keys were written.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("could not restrict access to the key directory %s: %w", dir, err)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("the master key is not usable: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &FileKeyStore{dir: dir, aead: aead}, nil
}

// DeriveMasterKey turns a passphrase into a master key.
//
// The salt must be stored alongside the key directory and must not be secret;
// it must, however, be unique per store, or two stores protected by the same
// passphrase share a master key. Use NewSalt to make one.
//
// The iteration count is deliberately not a parameter: a caller choosing it is a
// caller who can choose badly, and a low count is invisible until someone tries
// the passphrases.
func DeriveMasterKey(passphrase string, salt []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("an empty passphrase protects nothing")
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("the salt must be at least 16 bytes, this one is %d", len(salt))
	}
	return pbkdf2.Key(sha256.New, passphrase, salt, 600_000, masterKeyLen)
}

// NewSalt returns a fresh salt for DeriveMasterKey.
func NewSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("could not read randomness for a salt: %w", err)
	}
	return salt, nil
}

// fileName encodes a key name into something safe to use as a filename.
//
// Key names contain slashes, so they cannot be used directly without writing
// outside the directory. Encoded rather than sanitised: sanitising maps two
// different names onto one file, which would silently make two keys collide.
func (f *FileKeyStore) fileName(name string) string {
	return filepath.Join(f.dir,
		base64.RawURLEncoding.EncodeToString([]byte(name))+".key")
}

// Generate creates a new key under a name and writes it to disk.
func (f *FileKeyStore) Generate(name string, transferable bool) (Signer, error) {
	if name == "" {
		return nil, fmt.Errorf("a key needs a name to be found by later")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("could not read randomness for a new key: %w", err)
	}
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("could not read randomness for a nonce: %w", err)
	}
	// The name is authenticated but not encrypted, so a file cannot be moved to
	// a different name without the decryption failing.
	sealed := f.aead.Seal(nil, nonce, seed, []byte(name))

	record := storedKey{
		Version:      keyFileVersion,
		Name:         name,
		Transferable: transferable,
		Nonce:        base64.RawURLEncoding.EncodeToString(nonce),
		Sealed:       base64.RawURLEncoding.EncodeToString(sealed),
	}
	body, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}

	// O_EXCL makes "refuse to replace" the filesystem's job rather than a check
	// that another process could slip between.
	fh, err := os.OpenFile(f.fileName(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("a key named %q already exists; refusing to replace it, "+
				"because an identity may already have committed to it", name)
		}
		return nil, fmt.Errorf("could not write the key %q: %w", name, err)
	}
	if _, err := fh.Write(body); err != nil {
		fh.Close()
		return nil, fmt.Errorf("could not write the key %q: %w", name, err)
	}
	// Sync before reporting success. A key reported as created but lost to a
	// crash is the unrecoverable case this whole type exists to avoid.
	if err := fh.Sync(); err != nil {
		fh.Close()
		return nil, fmt.Errorf("could not flush the key %q to disk: %w", name, err)
	}
	if err := fh.Close(); err != nil {
		return nil, fmt.Errorf("could not close the key %q: %w", name, err)
	}
	return NewSoftwareSigner(seed, transferable)
}

// Signer returns the signer for a key previously generated.
func (f *FileKeyStore) Signer(name string) (Signer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	body, err := os.ReadFile(f.fileName(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no key named %q is held", name)
		}
		return nil, fmt.Errorf("could not read the key %q: %w", name, err)
	}
	var record storedKey
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, fmt.Errorf("the key file for %q is not readable: %w", name, err)
	}
	if record.Version != keyFileVersion {
		return nil, fmt.Errorf("the key file for %q is version %d and this build "+
			"understands version %d", name, record.Version, keyFileVersion)
	}
	if record.Name != name {
		return nil, fmt.Errorf("the key file found for %q says it is %q; the store has "+
			"been tampered with or copied from elsewhere", name, record.Name)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(record.Nonce)
	if err != nil {
		return nil, fmt.Errorf("the key file for %q has an unreadable nonce: %w", name, err)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(record.Sealed)
	if err != nil {
		return nil, fmt.Errorf("the key file for %q is unreadable: %w", name, err)
	}
	seed, err := f.aead.Open(nil, nonce, sealed, []byte(name))
	if err != nil {
		return nil, fmt.Errorf("the key %q could not be decrypted; either the master key "+
			"is wrong or the file has been altered: %w", name, err)
	}
	return NewSoftwareSigner(seed, record.Transferable)
}

// Names lists the keys held, sorted. Reveals no key material.
func (f *FileKeyStore) Names() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, fmt.Errorf("could not list the key directory: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(e.Name(), ".key"))
		if err != nil {
			// A file this store did not write. Skipped rather than reported as
			// a key, and not an error: a directory may hold other things.
			continue
		}
		out = append(out, string(raw))
	}
	sort.Strings(out)
	return out, nil
}
