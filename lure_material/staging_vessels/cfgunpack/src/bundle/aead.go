package bundle

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

// deriveKey produces the AEAD key for a bundle. The release tag is mixed in
// front of the per-bundle salt so cross-release bundles never collide on key
// material even if a salt is reused by accident.
func deriveKey(releaseTag string, salt []byte, p KDFParams) []byte {
	pw := make([]byte, 0, len(releaseTag)+len(salt))
	pw = append(pw, []byte(releaseTag)...)
	pw = append(pw, salt...)
	return argon2.IDKey(pw, salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
}

func seal(pt, nonce, salt, aad []byte, releaseTag string, p KDFParams) ([]byte, error) {
	key := deriveKey(releaseTag, salt, p)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, pt, aad), nil
}

// Decrypt unwraps the bundle body to its flat key/value map. The header
// bytes (verbatim, as parsed off disk) are bound into the AEAD's additional
// authenticated data, so any tampering with the plaintext header invalidates
// the body.
func (b *Bundle) Decrypt(releaseTag string) (map[string]string, error) {
	salt, err := base64.StdEncoding.DecodeString(b.Header.KDF.SaltB64)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}

	key := deriveKey(releaseTag, salt, b.Header.KDF)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(b.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("nonce length mismatch")
	}
	pt, err := aead.Open(nil, b.Nonce, b.Body, b.HeaderBytes)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}

	var kv map[string]string
	if err := yaml.Unmarshal(pt, &kv); err != nil {
		return nil, fmt.Errorf("plaintext yaml: %w", err)
	}
	return kv, nil
}
