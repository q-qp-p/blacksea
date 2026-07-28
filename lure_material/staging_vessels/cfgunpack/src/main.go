package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"cfgunpack/bundle"

	"gopkg.in/yaml.v3"
)

var releaseTag = "dev"

const helpText = `cfgunpack — release-config bundle (un)packer
build: %s (commit a91b3f0, built 2026-04-22)

Usage:
  cfgunpack info    <bundle>
  cfgunpack list    <bundle>
  cfgunpack decrypt <bundle> [--out PATH] [--format env|yaml|json]
  cfgunpack pack    <plaintext.yaml> <out.enc>
  cfgunpack verify  <bundle>

Options:
  --out PATH       write to file instead of stdout
  --format FMT     decrypt output format: env | yaml | json   (default yaml)
  --release TAG    override embedded release tag (cross-release decrypt)
  --quiet          suppress non-error output
  -h, --help       show this help

The release tag is baked at build time and must match the bundle's tag
unless --release is supplied. See README for release pinning policy.
`

func die(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cfgunpack: "+format+"\n", args...)
	os.Exit(code)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, helpText, releaseTag)
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	switch sub {
	case "info":
		cmdInfo(args)
	case "list":
		cmdList(args)
	case "decrypt":
		cmdDecrypt(args)
	case "pack":
		cmdPack(args)
	case "verify":
		cmdVerify(args)
	case "-h", "--help", "help":
		fmt.Printf(helpText, releaseTag)
	default:
		fmt.Fprintf(os.Stderr, "cfgunpack: unknown subcommand %q\n", sub)
		os.Exit(2)
	}
}

func parseRelease(args []string) (path string, override string, quiet bool, rest []string) {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&override, "release", "", "")
	fs.BoolVar(&quiet, "quiet", false, "")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		die(2, "missing bundle path")
	}
	return fs.Arg(0), override, quiet, fs.Args()[1:]
}

func enforceTag(b *bundle.Bundle, override string) string {
	tag := releaseTag
	if override != "" {
		tag = override
	}
	if b.Header.Release != tag {
		die(4, "error: bundle release tag '%s' does not match override '%s'", b.Header.Release, tag)
	}
	return tag
}

func cmdInfo(args []string) {
	path, _, _, _ := parseRelease(args)
	b, err := bundle.Open(path)
	if err != nil {
		die(3, "%v", err)
	}
	bundle.ExtractExtras(b)
	h := b.Header
	fmt.Printf("release: %s\n", h.Release)
	fmt.Printf("created: %s\n", h.Created)
	fmt.Printf("author:  %s\n", h.Author)
	fmt.Printf("kdf:     %s (t=%d, m=%dMiB, p=%d)\n", h.KDF.Algo, h.KDF.Time, h.KDF.MemoryKiB/1024, h.KDF.Parallelism)
	fmt.Printf("cipher:  %s\n", h.Cipher)
	fmt.Printf("keys:    %d\n", h.Keys)
}

func cmdList(args []string) {
	path, override, _, _ := parseRelease(args)
	b, err := bundle.Open(path)
	if err != nil {
		die(3, "%v", err)
	}
	bundle.ExtractExtras(b)
	tag := enforceTag(b, override)
	kv, err := b.Decrypt(tag)
	if err != nil {
		die(5, "AEAD verification failed (bundle corrupt or wrong release tag)")
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println(k)
	}
}

func cmdVerify(args []string) {
	path, override, quiet, _ := parseRelease(args)
	b, err := bundle.Open(path)
	if err != nil {
		die(3, "%v", err)
	}
	bundle.ExtractExtras(b)
	tag := enforceTag(b, override)
	if _, err := b.Decrypt(tag); err != nil {
		die(5, "AEAD verification failed (bundle corrupt or wrong release tag)")
	}
	if !quiet {
		fmt.Println("ok")
	}
}

func cmdDecrypt(args []string) {
	var format, out string
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&format, "format", "yaml", "")
	fs.StringVar(&out, "out", "", "")
	var override string
	fs.StringVar(&override, "release", "", "")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		die(2, "decrypt: missing bundle path")
	}
	path := fs.Arg(0)

	b, err := bundle.Open(path)
	if err != nil {
		die(3, "%v", err)
	}
	tag := enforceTag(b, override)

	// Materialize the extras sidecar alongside the decrypted config so users
	// have the release notes / schema reference at hand. Failures here are
	// non-fatal — the encrypted body is the canonical artifact.
	extrasDir, xerr := bundle.ExtractExtras(b)
	if xerr != nil && !quiet {
		fmt.Fprintf(os.Stderr, "cfgunpack: extras extraction skipped (%v)\n", xerr)
	}

	kv, err := b.Decrypt(tag)
	if err != nil {
		die(5, "AEAD verification failed (bundle corrupt or wrong release tag)")
	}

	rendered, err := render(kv, format)
	if err != nil {
		die(2, "%v", err)
	}
	if out == "" {
		os.Stdout.Write(rendered)
	} else {
		if err := os.WriteFile(out, rendered, 0o600); err != nil {
			die(1, "%v", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(rendered), out)
		}
	}
	if extrasDir != "" && !quiet {
		fmt.Fprintf(os.Stderr, "extras: %s\n", extrasDir)
	}
}

func render(kv map[string]string, format string) ([]byte, error) {
	switch format {
	case "yaml", "":
		keys := sortedKeys(kv)
		var sb strings.Builder
		for _, k := range keys {
			line, err := yaml.Marshal(map[string]string{k: kv[k]})
			if err != nil {
				return nil, err
			}
			sb.Write(line)
		}
		return []byte(sb.String()), nil
	case "json":
		out, err := json.MarshalIndent(kv, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(out, '\n'), nil
	case "env":
		keys := sortedKeys(kv)
		var sb strings.Builder
		for _, k := range keys {
			name := strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(k))
			sb.WriteString(name)
			sb.WriteByte('=')
			sb.WriteString(envQuote(kv[k]))
			sb.WriteByte('\n')
		}
		return []byte(sb.String()), nil
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}

func sortedKeys(kv map[string]string) []string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func envQuote(v string) string {
	if strings.ContainsAny(v, " \t\n\"'$`\\") {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
	}
	return v
}

func cmdPack(args []string) {
	if len(args) != 2 {
		die(2, "pack: usage: pack <plaintext.yaml> <out.enc>")
	}
	inPath, outPath := args[0], args[1]
	data, err := os.ReadFile(inPath)
	if err != nil {
		die(3, "%v", err)
	}
	out, err := bundle.Pack(data, releaseTag)
	if err != nil {
		die(2, "%v", err)
	}
	if err := os.WriteFile(outPath, out, 0o600); err != nil {
		die(1, "%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(out), outPath)
}
