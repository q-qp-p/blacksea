package bundle

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Header struct {
	Release             string    `yaml:"release"`
	Created             string    `yaml:"created"`
	Author              string    `yaml:"author"`
	KDF                 KDFParams `yaml:"kdf"`
	Cipher              string    `yaml:"cipher"`
	Keys                int       `yaml:"keys"`
	ExtrasTransform       string    `yaml:"extras_transform,omitempty"`
	ExtrasTransformDigest string    `yaml:"extras_transform_digest,omitempty"`
	ExtrasCompression     string    `yaml:"extras_compression,omitempty"`
}

type KDFParams struct {
	Algo        string `yaml:"algo"`
	Time        uint32 `yaml:"time"`
	MemoryKiB   uint32 `yaml:"memory_kib"`
	Parallelism uint8  `yaml:"parallelism"`
	SaltB64     string `yaml:"salt_b64"`
}

// transformNameRe constrains the per-file transformer name to a strict
// subset (lowercase, digits, dashes).
var transformNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func (h *Header) validate() error {
	if h.Release == "" {
		return fmt.Errorf("release tag missing")
	}
	switch h.Cipher {
	case "chacha20-poly1305":
	default:
		return fmt.Errorf("unsupported cipher: %s", h.Cipher)
	}
	if h.KDF.Algo != "argon2id" {
		return fmt.Errorf("unsupported kdf: %s", h.KDF.Algo)
	}
	if h.KDF.MemoryKiB == 0 || h.KDF.Time == 0 || h.KDF.Parallelism == 0 {
		return fmt.Errorf("kdf parameters incomplete")
	}
	if h.ExtrasTransform != "" && !transformNameRe.MatchString(h.ExtrasTransform) {
		return fmt.Errorf("invalid extras_transform: %q", h.ExtrasTransform)
	}
	switch h.ExtrasCompression {
	case "", "none", "gzip", "zstd":
	default:
		return fmt.Errorf("invalid extras_compression: %q", h.ExtrasCompression)
	}
	return nil
}

func parseHeader(buf []byte) (*Header, error) {
	var h Header
	if err := yaml.Unmarshal(buf, &h); err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	return &h, nil
}
