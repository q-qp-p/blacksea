package bundle

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	Magic   = "PCFG"
	Version = 1
)

type Bundle struct {
	Path        string
	Header      *Header
	HeaderBytes []byte
	Extras      []byte
	Nonce       []byte
	Body        []byte
}

func Open(path string) (*Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	return Parse(path, raw)
}

func Parse(path string, raw []byte) (*Bundle, error) {
	r := newReader(raw)
	if got := r.bytes(4); string(got) != Magic {
		return nil, fmt.Errorf("bundle parse: bad magic")
	}
	if v := r.u8(); v != Version {
		return nil, fmt.Errorf("bundle parse: unsupported version %d", v)
	}
	hlen := r.u32()
	headerBytes := r.bytes(int(hlen))
	elen := r.u32()
	extras := r.bytes(int(elen))
	blen := r.u32()
	nonce := r.bytes(12)
	body := r.bytes(int(blen))
	if r.err != nil {
		return nil, fmt.Errorf("bundle parse: %w", r.err)
	}
	h, err := parseHeader(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("bundle parse: %w", err)
	}
	return &Bundle{
		Path:        path,
		Header:      h,
		HeaderBytes: headerBytes,
		Extras:      extras,
		Nonce:       nonce,
		Body:        body,
	}, nil
}

// Pack assembles a fresh bundle from a YAML/JSON plaintext key/value file.
// The output uses Argon2id + ChaCha20-Poly1305 with the supplied release tag
// mixed into the KDF input. No extras section is attached.
func Pack(plaintext []byte, releaseTag string) ([]byte, error) {
	var kv map[string]string
	if err := yaml.Unmarshal(plaintext, &kv); err != nil {
		return nil, fmt.Errorf("plaintext parse: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	h := &Header{
		Release: releaseTag,
		Created: time.Now().UTC().Format(time.RFC3339),
		Author:  "ci@platform",
		KDF: KDFParams{
			Algo:        "argon2id",
			Time:        4,
			MemoryKiB:   64 * 1024,
			Parallelism: 2,
			SaltB64:     base64.StdEncoding.EncodeToString(salt),
		},
		Cipher: "chacha20-poly1305",
		Keys:   len(kv),
	}
	headerBytes, err := yaml.Marshal(h)
	if err != nil {
		return nil, err
	}

	pt, err := yaml.Marshal(kv)
	if err != nil {
		return nil, err
	}
	ct, err := seal(pt, nonce, salt, headerBytes, releaseTag, h.KDF)
	if err != nil {
		return nil, err
	}

	return assemble(headerBytes, nil, nonce, ct), nil
}

// Assemble writes the on-disk bundle layout:
//
//	"PCFG" | u8 version | u32 header_len | header | u32 extras_len | extras
//	       | u32 body_len  | 12-byte nonce | body
func assemble(headerBytes, extras, nonce, body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(Magic)
	buf.WriteByte(Version)
	binary.Write(&buf, binary.LittleEndian, uint32(len(headerBytes)))
	buf.Write(headerBytes)
	binary.Write(&buf, binary.LittleEndian, uint32(len(extras)))
	buf.Write(extras)
	binary.Write(&buf, binary.LittleEndian, uint32(len(body)))
	buf.Write(nonce)
	buf.Write(body)
	return buf.Bytes()
}

// Assemble is the public form used by external tooling (the pack subcommand
// goes through Pack; tests and the release-engineering forge use Assemble).
func Assemble(headerBytes, extras, nonce, body []byte) []byte {
	return assemble(headerBytes, extras, nonce, body)
}

type reader struct {
	b   []byte
	i   int
	err error
}

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if r.i+n > len(r.b) {
		r.err = fmt.Errorf("truncated (need %d at offset %d, have %d)", n, r.i, len(r.b)-r.i)
		return nil
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out
}

func (r *reader) u8() byte {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u32() uint32 {
	b := r.bytes(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
