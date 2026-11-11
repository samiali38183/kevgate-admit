package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type obs struct {
	mu       sync.Mutex
	ok, errs int
}

func (o *obs) Reloaded(_ string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil {
		o.errs++
	} else {
		o.ok++
	}
}

func writePair(t *testing.T, dir string, host string) []byte {
	t.Helper()
	cert, caPEM, err := SelfSigned([]string{host}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return caPEM
}

func leafHosts(t *testing.T, r *Reloader) []string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return append(x.DNSNames, ipStrings(x)...)
}

func ipStrings(x *x509.Certificate) []string {
	var out []string
	for _, ip := range x.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func TestReloaderPicksUpNewCertificate(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "one.example")
	o := &obs{}
	r, err := NewReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), o)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Ready() || leafHosts(t, r)[0] != "one.example" {
		t.Fatal("initial certificate not served")
	}
	if changed, err := r.Reload(); changed || err != nil {
		t.Fatalf("unchanged reload: %v %v", changed, err)
	}
	writePair(t, dir, "two.example")
	if changed, err := r.Reload(); !changed || err != nil {
		t.Fatalf("rotation: %v %v", changed, err)
	}
	if leafHosts(t, r)[0] != "two.example" {
		t.Error("new certificate not served after reload")
	}
	// A broken rotation keeps serving the previous certificate.
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reload(); err == nil {
		t.Fatal("expected error for broken key")
	}
	if leafHosts(t, r)[0] != "two.example" {
		t.Error("previous certificate lost after failed reload")
	}
	if o.ok != 1 || o.errs != 1 {
		t.Errorf("observer ok=%d errs=%d", o.ok, o.errs)
	}
	_ = os.Remove(filepath.Join(dir, "tls.key"))
	if _, err := r.Reload(); err == nil {
		t.Error("missing key file must error")
	}
}

func TestNewReloaderErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewReloader(filepath.Join(dir, "a"), filepath.Join(dir, "b"), nil); err == nil {
		t.Error("missing files")
	}
	_ = os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600)
	if _, err := NewReloader(filepath.Join(dir, "a"), filepath.Join(dir, "b"), nil); err == nil {
		t.Error("missing key")
	}
	_ = os.WriteFile(filepath.Join(dir, "b"), []byte("y"), 0o600)
	if _, err := NewReloader(filepath.Join(dir, "a"), filepath.Join(dir, "b"), nil); err == nil {
		t.Error("garbage pair")
	}
}

func TestRunReloadsInBackground(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "one.example")
	r, err := NewReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		r.Run(ctx, 10*time.Millisecond, func(e error) {
			select {
			case errs <- e:
			default:
			}
		})
		close(done)
	}()
	writePair(t, dir, "two.example")
	deadline := time.Now().Add(3 * time.Second)
	for leafHosts(t, r)[0] != "two.example" {
		if time.Now().After(deadline) {
			t.Fatal("rotation not picked up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// On Windows a remove can fail while the reloader still has the file open,
	// so retry until it goes through.
	rmDeadline := time.Now().Add(3 * time.Second)
	for os.Remove(filepath.Join(dir, "tls.crt")) != nil {
		if _, err := os.Stat(filepath.Join(dir, "tls.crt")); os.IsNotExist(err) {
			break
		}
		if time.Now().After(rmDeadline) {
			t.Fatal("could not remove the certificate file")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Drain errors from the rotation above (a half-written pair can fail once)
	// so only an error caused by the removal counts.
	for drained := false; !drained; {
		select {
		case <-errs:
		default:
			drained = true
		}
	}
	select {
	case <-errs:
	case <-time.After(5 * time.Second):
		t.Fatal("onError not called")
	}
	cancel()
	<-done
}

func TestSelfSignedHandshake(t *testing.T) {
	cert, caPEM, err := SelfSigned([]string{"webhook.test.svc", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := Static(cert)
	if changed, err := r.Reload(); changed || err != nil {
		t.Fatalf("static reload must be a no-op: %v %v", changed, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA PEM unusable")
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	for _, name := range []string{"webhook.test.svc"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name}); err != nil {
			t.Errorf("verify %s: %v", name, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "evil.example"}); err == nil {
		t.Error("certificate verified for a name it does not cover")
	}
	if cfg := r.Config(); cfg.MinVersion < tls.VersionTLS12 || cfg.GetCertificate == nil {
		t.Errorf("config = %+v", cfg)
	}
	if _, _, err := SelfSigned(nil, time.Hour); err == nil {
		t.Error("no hosts must fail")
	}
	if _, err := (&Reloader{}).GetCertificate(nil); err == nil {
		t.Error("empty reloader must fail")
	}
}
