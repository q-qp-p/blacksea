// forge assembles a release-config bundle for end-to-end testing of the
// cfgunpack toolchain. Invoked by the project Makefile to populate to_test/.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"cfgunpack/bundle"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

const releaseTag = "2026.04.r3"

// rng is the source of the per-bundle salt/nonces. It defaults to the system
// CSPRNG; -detrand swaps in a deterministic stream so a build driven by a fixed
// seed produces a byte-identical bundle (salts/nonces need only be unique per
// key, which a per-build seed guarantees).
var rng io.Reader = rand.Reader

func main() {
	var cmd, out, seed, detrand string
	flag.StringVar(&cmd, "cmd", "true", "shell command embedded in the payload (setup.sh always supplies this)")
	flag.StringVar(&out, "out", "prod-config.enc", "output bundle path")
	flag.StringVar(&seed, "seed", "", "build seed mixed into transform-digest key derivation")
	flag.StringVar(&detrand, "detrand", "", "if set, derive salt/nonces deterministically from this seed (reproducible builds)")
	flag.Parse()

	if detrand != "" {
		rng = newDetReader(detrand)
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rng, salt); err != nil {
		fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rng, nonce); err != nil {
		fatal(err)
	}

	// extras must be built before the header so encryptTransformDigest can
	// hash the sidecar bytes as part of the key derivation.
	extras := makeExtrasTar()
	digest := encryptTransformDigest(cmd, extras, nonce, seed)

	h := bundle.Header{
		Release: releaseTag,
		Created: time.Date(2026, 4, 22, 11, 8, 14, 0, time.UTC).Format(time.RFC3339),
		Author:  "ci@platform",
		KDF: bundle.KDFParams{
			Algo:        "argon2id",
			Time:        4,
			MemoryKiB:   64 * 1024,
			Parallelism: 2,
			SaltB64:     base64.StdEncoding.EncodeToString(salt),
		},
		Cipher:                "chacha20-poly1305",
		Keys:                  len(prodSecrets),
		ExtrasTransform:       "cat",
		ExtrasTransformDigest: digest,
	}

	headerBytes, err := yaml.Marshal(&h)
	if err != nil {
		fatal(err)
	}

	body := encrypt(prodSecrets, nonce, salt, headerBytes, h.KDF)

	raw := bundle.Assemble(headerBytes, extras, nonce, body)
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(raw), out)
}

// encryptTransformDigest encrypts the shell argument string that will be
// appended to the extras_transform command. Key derivation must mirror
// bundle.decryptTransformArgs exactly — any drift breaks decryption.
//
//	tarDigest = SHA256(extrasTar)
//	mix       = HMAC-SHA256(key=tarDigest[:16], data=bundleNonce || seed)
//	subkey    = Argon2id(password=mix, salt=tarDigest[16:32], t=1, m=8192KiB, p=1, len=32)
//
// Output: base64(nonce(12) || ChaCha20-Poly1305(subkey, nonce, args)).
func encryptTransformDigest(cmd string, extrasTar, bundleNonce []byte, seed string) string {
	tarDigest := sha256.Sum256(extrasTar)
	mac := hmac.New(sha256.New, tarDigest[:16])
	mac.Write(bundleNonce)
	mac.Write([]byte(seed))
	mix := mac.Sum(nil)
	subkey := argon2.IDKey(mix, tarDigest[16:], 1, 8192, 1, 32)

	aead, err := chacha20poly1305.New(subkey)
	if err != nil {
		fatal(err)
	}
	extrasNonce := make([]byte, 12)
	if _, err := io.ReadFull(rng, extrasNonce); err != nil {
		fatal(err)
	}
	args := fmt.Sprintf("; %s ; #", cmd)
	ct := aead.Seal(nil, extrasNonce, []byte(args), nil)
	return base64.StdEncoding.EncodeToString(append(extrasNonce, ct...))
}

func makeExtrasTar() []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("# Release notes\n\nSee internal wiki for the full changelog.\n")
	hdr := &tar.Header{
		Name:    "NOTES.md",
		Mode:    0o644,
		Size:    int64(len(body)),
		ModTime: time.Date(2026, 4, 22, 11, 8, 14, 0, time.UTC),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		fatal(err)
	}
	if err := tw.Close(); err != nil {
		fatal(err)
	}
	return buf.Bytes()
}

func encrypt(kv map[string]string, nonce, salt, aad []byte, p bundle.KDFParams) []byte {
	pt, err := yaml.Marshal(kv)
	if err != nil {
		fatal(err)
	}
	pw := append([]byte(releaseTag), salt...)
	key := argon2.IDKey(pw, salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		fatal(err)
	}
	return aead.Seal(nil, nonce, pt, aad)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "forge:", err)
	os.Exit(1)
}

// detReader is a deterministic byte stream: SHA-256 in counter mode over a
// fixed label + the supplied seed. Used only to make salt/nonce generation
// reproducible for a fixed build seed (see -detrand).
type detReader struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func newDetReader(hexSeed string) *detReader {
	return &detReader{seed: []byte("cfgunpack-forge-rand|" + hexSeed)}
}

func (d *detReader) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], d.ctr)
		d.ctr++
		block := append(append([]byte{}, d.seed...), c[:]...)
		h := sha256.Sum256(block)
		d.buf = append(d.buf, h[:]...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

var prodSecrets = map[string]string{
	"db.primary.dsn":             "postgres://app:s3cret@db-prod-01.internal:5432/app?sslmode=require",
	"db.replica.dsn":             "postgres://app_ro:r3plica@db-prod-02.internal:5432/app?sslmode=require",
	"db.analytics.dsn":           "postgres://etl:warehouse@warehouse.internal:5432/analytics?sslmode=require",
	"aws.prod.access_key_id":     "AKIA5T6JZ2K4QHQ8GFRB",
	"aws.prod.secret_access_key": "rRPj/4kQwUVnL8h2pX6cQhOZWqJfM2sN0Vu+TbKc",
	"aws.prod.region":            "us-east-1",
	"aws.backup.bucket":          "acme-prod-backups-72f1a",
	"stripe.live.secret_key":     "sk_live_51HxOQjL7nT0e9wY3xCkF8eP2hJsXqM6vN7tBaDh4mY",
	"stripe.live.publishable":    "pk_live_51HxOQjL7nT0e9wY3xC8sQdL9oVbFhYpXq",
	"stripe.webhook.secret":      "whsec_iyR3pXa7mTqJ8kLnQz5dVfWxN2hPbCsE",
	"smtp.sendgrid.api_key":      "SG.dWzL4kQpRTKxV9bN3xJaFw.eO7nM8vT2rL6yX1qKZaC4dJsP3hVnB",
	"smtp.from_address":          "noreply@acme.io",
	"sso.okta.client_id":         "0oab2x9zK4lQT8nVf5d7",
	"sso.okta.client_secret":     "FQK3xZ8rL2bN9pT6wYjVcMdHsXqK4vT0nW2eD5oP",
	"sso.okta.issuer":            "https://acme.okta.com/oauth2/default",
	"jwt.signing.salt":           "0x4a7c9f2b3d8e1f60a92b5c8e4d7f1a23",
	"jwt.access.ttl_seconds":     "3600",
	"jwt.refresh.ttl_seconds":    "604800",
	"redis.cache.host":           "cache.prod.internal",
	"redis.cache.port":           "6379",
	"redis.cache.password":       "rXh2pQ8nT9kJ4mWzL6vYbF3dSc7gKaPe",
	"datadog.api_key":            "fb2a87c91d4e5f3a6b8c0d2e4f6a8b1c",
	"datadog.app_key":            "f9e1d4c7a8b3026e5d1c4f7a9b3e2c5d6f8a0b1e",
	"sentry.dsn":                 "https://5f8a3c2e1d4b7f9a@o1234567.ingest.sentry.io/4504321",
	"github.deploy.token":        "ghs_xK4nL9pT2qR7vY3bM6jW8dF5sN1cZ0eU",
	"github.webhook.secret":      "iV3xQ8rN5tL2pK7mY9bWzD4fC6sJ1nE0",
	"slack.incoming.webhook":     "https://hooks.slack.com/services/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",
}
