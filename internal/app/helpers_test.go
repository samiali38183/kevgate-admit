package app

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/samiali38183/kevgate-admit/internal/tlsutil"
)

// writeCert writes a certificate and key the way a cert-manager secret mount
// looks (tls.crt and tls.key).
func writeCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	cert, pemCert, err := tlsutil.SelfSigned([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(c, pemCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return c, k
}
