package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samiali38183/kevgate-admit/internal/evsign"
)

func signedDir(t *testing.T, kind evsign.Kind) (dir string, priv []byte, p *DirProvider) {
	t.Helper()
	priv, pub, err := evsign.GenerateKey(kind)
	if err != nil {
		t.Fatal(err)
	}
	v, err := evsign.NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	return dir, priv, &DirProvider{Dir: dir, Verifier: v}
}

func writeSig(t *testing.T, dir string, priv []byte, digest string, body string) {
	t.Helper()
	k, err := evsign.ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := evsign.Sign(k, digest, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	name, _ := FileName(digest)
	if err := os.WriteFile(filepath.Join(dir, name+evsign.Suffix), sig, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDirProviderSignatureStates(t *testing.T) {
	for _, kind := range []evsign.Kind{evsign.Ed25519, evsign.ECDSA} {
		t.Run(string(kind), func(t *testing.T) {
			dir, priv, p := signedDir(t, kind)
			ctx := context.Background()

			// valid
			writeReport(t, dir, dA, report(dA))
			writeSig(t, dir, priv, dA, report(dA))
			ev, err := p.Lookup(ctx, dA)
			if err != nil || ev.Signature != SigVerified || ev.SigDetail != "" || len(ev.Findings) != 1 {
				t.Fatalf("valid: %+v %v", ev, err)
			}

			// tampered after signing
			tampered := strings.Replace(report(dA), "7.5", "1.5", 1)
			writeReport(t, dir, dA, tampered)
			ev, err = p.Lookup(ctx, dA)
			if err != nil || ev.Signature != SigInvalid || !strings.Contains(ev.SigDetail, "does not verify") {
				t.Fatalf("tampered: %+v %v", ev, err)
			}

			// no signature file
			writeReport(t, dir, dB, report(dB))
			ev, err = p.Lookup(ctx, dB)
			if err != nil || ev.Signature != SigMissing || !strings.Contains(ev.SigDetail, FileNameMust(t, dB)+".sig") {
				t.Fatalf("missing: %+v %v", ev, err)
			}

			// a signature made for another digest, copied next to this report
			sigA, _ := os.ReadFile(filepath.Join(dir, FileNameMust(t, dA)+".sig"))
			if err := os.WriteFile(filepath.Join(dir, FileNameMust(t, dB)+".sig"), sigA, 0o600); err != nil {
				t.Fatal(err)
			}
			ev, _ = p.Lookup(ctx, dB)
			if ev.Signature != SigInvalid {
				t.Fatalf("replayed signature: %+v", ev)
			}

			// signed by a key that is not trusted
			_, otherPriv, _ := signedDir(t, kind)
			writeSig(t, dir, otherPriv, dB, report(dB))
			ev, _ = p.Lookup(ctx, dB)
			if ev.Signature != SigInvalid {
				t.Fatalf("untrusted key: %+v", ev)
			}
		})
	}
}

func FileNameMust(t *testing.T, d string) string {
	t.Helper()
	n, err := FileName(d)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDirProviderSignatureEdgeCases(t *testing.T) {
	dir, priv, p := signedDir(t, evsign.Ed25519)
	ctx := context.Background()
	writeReport(t, dir, dA, report(dA))

	// the .sig path is a directory
	if err := os.Mkdir(filepath.Join(dir, FileNameMust(t, dA)+".sig"), 0o700); err != nil {
		t.Fatal(err)
	}
	if ev, err := p.Lookup(ctx, dA); err != nil || ev.Signature != SigInvalid {
		t.Fatalf("directory as signature: %+v %v", ev, err)
	}
	_ = os.Remove(filepath.Join(dir, FileNameMust(t, dA)+".sig"))

	// an oversized signature file
	big := strings.Repeat("A", evsign.MaxSignatureFileBytes*2)
	if err := os.WriteFile(filepath.Join(dir, FileNameMust(t, dA)+".sig"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if ev, err := p.Lookup(ctx, dA); err != nil || ev.Signature != SigInvalid {
		t.Fatalf("oversize signature: %+v %v", ev, err)
	}

	// a signature without a report is not evidence
	writeSig(t, dir, priv, dB, report(dB))
	if _, err := p.Lookup(ctx, dB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan signature: %v", err)
	}

	// without a verifier the state stays not-checked, even when a .sig exists
	plain := &DirProvider{Dir: dir}
	writeSig(t, dir, priv, dA, report(dA))
	if ev, err := plain.Lookup(ctx, dA); err != nil || ev.Signature != SigNotChecked {
		t.Fatalf("no verifier: %+v %v", ev, err)
	}
}
