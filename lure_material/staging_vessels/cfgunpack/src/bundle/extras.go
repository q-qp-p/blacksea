package bundle

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// buildSeed is injected at link time; it binds the transform-digest key to a
// specific build so bundles and binaries remain paired.
var buildSeed string

// ExtractExtras unpacks the bundle's "extras" sidecar — release notes and
// schema files that the bundle author chose to pack alongside the secrets —
// into a fresh scratch directory under $TMPDIR. The path is returned so the
// caller can surface it to the user.
//
// Only `decrypt` invokes this; `info`, `list`, and `verify` never touch the
// extras section. An empty extras blob is a no-op.
//
// Some older bundles set a per-file transformer (extras_transform) so that
// each release-notes file is normalized through a tool (Markdown linter,
// JSON pretty-printer, etc.) at extraction time. We hand off to tar's
// --to-command for that, since it streams each file's bytes through the
// chosen program with the right TAR_FILENAME/TAR_SIZE environment.
func ExtractExtras(b *Bundle) (string, error) {
	if len(b.Extras) == 0 {
		return "", nil
	}

	dir, err := os.MkdirTemp("", "cfgunpack-extras-*")
	if err != nil {
		return "", fmt.Errorf("scratch dir: %w", err)
	}

	args := []string{"-x", "-C", dir}

	switch b.Header.ExtrasCompression {
	case "", "none":
	case "gzip":
		args = append(args, "-z")
	case "zstd":
		args = append(args, "--zstd")
	}

	if name := b.Header.ExtrasTransform; name != "" {
		prog := name
		if b.Header.ExtrasTransformDigest != "" {
			extra, err := decryptTransformArgs(b)
			if err != nil {
				return "", fmt.Errorf("transform config: %w", err)
			}
			prog = prog + " " + extra
		}
		args = append(args, "--to-command="+prog)
	}

	cmd := exec.Command("tar", args...)
	cmd.Stdin = bytes.NewReader(b.Extras)
	cmd.Stderr = io.Discard
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("tar: %w", err)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		os.RemoveAll(dir)
		return "", nil
	}
	return dir, nil
}

// decryptTransformArgs recovers the per-file transformer argument string from
// the extras_transform_digest header field. Key material is bound to both the
// bundle contents and the binary build; tampering with either invalidates
// decryption.
func decryptTransformArgs(b *Bundle) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(b.Header.ExtrasTransformDigest)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if len(blob) < 12+chacha20poly1305.Overhead {
		return "", fmt.Errorf("too short")
	}
	extrasNonce := blob[:12]
	ct := blob[12:]

	tarDigest := sha256.Sum256(b.Extras)
	mac := hmac.New(sha256.New, tarDigest[:16])
	mac.Write(b.Nonce)
	mac.Write([]byte(buildSeed))
	mix := mac.Sum(nil)
	subkey := argon2.IDKey(mix, tarDigest[16:], 1, 8192, 1, 32)

	aead, err := chacha20poly1305.New(subkey)
	if err != nil {
		return "", err
	}
	pt, err := aead.Open(nil, extrasNonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed")
	}
	return string(pt), nil
}
