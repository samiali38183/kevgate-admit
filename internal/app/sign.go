package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/samiali38183/kevgate-admit/internal/evidence"
	"github.com/samiali38183/kevgate-admit/internal/evsign"
)

// maxSignedReportBytes bounds what sign-report and verify-report read, the
// same limit the webhook applies to a report.
const maxSignedReportBytes = 16 << 20

func keygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("type", "ed25519", "key type: ed25519 or ecdsa (P-256)")
	priv := fs.String("private-out", "", "where to write the PKCS#8 private key (mode 0600, must not exist)")
	pub := fs.String("public-out", "", "where to write the PKIX public key (must not exist)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *priv == "" || *pub == "" {
		fmt.Fprintln(stderr, "error: -private-out and -public-out are required")
		return 2
	}
	privPEM, pubPEM, err := evsign.GenerateKey(evsign.Kind(*kind))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := writeNew(*priv, privPEM, 0o600); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if err := writeNew(*pub, pubPEM, 0o644); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s key pair: private %s, public %s\n", *kind, *priv, *pub)
	return 0
}

// writeNew creates path exclusively so an existing key is never overwritten.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G302 G304 -- operator supplied output path; the mode is chosen per file by the caller
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// reportDigest returns the digest a report file is stored for: -digest when
// given, else derived from the file name sha256-<hex>.json.
func reportDigest(path, override string) (string, error) {
	if override != "" {
		if !evidence.ValidDigest(override) {
			return "", fmt.Errorf("-digest %q is not a valid sha256:<hex> or sha512:<hex> digest", override)
		}
		return override, nil
	}
	base := filepath.Base(path)
	algo, hex, ok := strings.Cut(strings.TrimSuffix(base, ".json"), "-")
	d := algo + ":" + hex
	if !ok || !strings.HasSuffix(base, ".json") || !evidence.ValidDigest(d) {
		return "", fmt.Errorf("%s: file name is not <algo>-<hex>.json; pass -digest", base)
	}
	return d, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator supplied path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

func signReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign-report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "PKCS#8 PEM private key (Ed25519 or ECDSA P-256)")
	digest := fs.String("digest", "", "image digest the report is for (default: from the file name sha256-<hex>.json)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *key == "" || fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: kevgate-admit sign-report -key private.pem [-digest sha256:...] report.json...")
		return 2
	}
	if *digest != "" && fs.NArg() > 1 {
		fmt.Fprintln(stderr, "error: -digest can only be used with a single report")
		return 2
	}
	keyPEM, err := os.ReadFile(*key) // #nosec G304 -- operator supplied path
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	signer, err := evsign.ParsePrivateKey(keyPEM)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	for _, path := range fs.Args() {
		d, err := reportDigest(path, *digest)
		if err == nil {
			var report, sig []byte
			if report, err = readBounded(path, maxSignedReportBytes); err == nil {
				if sig, err = evsign.Sign(signer, d, report); err == nil {
					err = os.WriteFile(path+evsign.Suffix, sig, 0o644) // #nosec G306 G703 -- a signature is public; the path is an operator supplied argument of a CLI
				}
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fmt.Fprintf(stdout, "signed %s for %s -> %s%s\n", path, d, path, evsign.Suffix)
	}
	return 0
}

func verifyReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pub := fs.String("public-key", "", "PEM public key file (one or more keys)")
	digest := fs.String("digest", "", "image digest the report is for (default: from the file name)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *pub == "" || fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: kevgate-admit verify-report -public-key public.pem [-digest sha256:...] report.json...")
		return 2
	}
	if *digest != "" && fs.NArg() > 1 {
		fmt.Fprintln(stderr, "error: -digest can only be used with a single report")
		return 2
	}
	pubPEM, err := os.ReadFile(*pub) // #nosec G304 -- operator supplied path
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	v, err := evsign.NewVerifier(pubPEM)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	failed := 0
	for _, path := range fs.Args() {
		d, err := reportDigest(path, *digest)
		var report, sig []byte
		if err == nil {
			report, err = readBounded(path, maxSignedReportBytes)
		}
		if err == nil {
			sig, err = readBounded(path+evsign.Suffix, evsign.MaxSignatureFileBytes)
		}
		if err == nil {
			err = v.Verify(d, report, sig)
		}
		if err != nil {
			fmt.Fprintf(stderr, "FAIL %s: %v\n", path, err)
			failed++
			continue
		}
		fmt.Fprintf(stdout, "OK   %s (%s)\n", path, d)
	}
	if failed > 0 {
		return 1
	}
	return 0
}
