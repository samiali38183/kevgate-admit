// Package tlsutil provides certificate reloading for mounted secrets
// (cert-manager style) and a self-signed certificate generator for CI and
// local development.
package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// Observer receives reload outcomes.
type Observer interface {
	Reloaded(component string, err error)
}

// Reloader serves a certificate read from disk and picks up changes.
type Reloader struct {
	certFile, keyFile string
	obs               Observer
	cur               atomic.Pointer[tls.Certificate]
	sum               atomic.Pointer[[sha256.Size]byte]
}

// NewReloader loads the pair once and fails if it is not usable.
func NewReloader(certFile, keyFile string, obs Observer) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile, obs: obs}
	if _, err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// Static wraps a fixed certificate, for the self-signed mode.
func Static(c tls.Certificate) *Reloader {
	r := &Reloader{}
	r.cur.Store(&c)
	return r
}

func (r *Reloader) load() (bool, error) {
	cert, err := os.ReadFile(r.certFile)
	if err != nil {
		return false, fmt.Errorf("tls: %w", err)
	}
	key, err := os.ReadFile(r.keyFile)
	if err != nil {
		return false, fmt.Errorf("tls: %w", err)
	}
	sum := sha256.Sum256(append(append([]byte{}, cert...), key...))
	if old := r.sum.Load(); old != nil && *old == sum {
		return false, nil
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return false, fmt.Errorf("tls: %w", err)
	}
	r.cur.Store(&pair)
	r.sum.Store(&sum)
	return true, nil
}

// Reload re-reads the files. A pair that does not parse leaves the previous
// certificate in place.
func (r *Reloader) Reload() (bool, error) {
	if r.certFile == "" {
		return false, nil
	}
	changed, err := r.load()
	if r.obs != nil && (changed || err != nil) {
		r.obs.Reloaded("tls", err)
	}
	return changed, err
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := r.cur.Load()
	if c == nil {
		return nil, errors.New("tls: no certificate loaded")
	}
	return c, nil
}

// Ready reports whether a certificate is loaded.
func (r *Reloader) Ready() bool { return r.cur.Load() != nil }

// Run polls for changes until ctx is cancelled.
func (r *Reloader) Run(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.Reload(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// Config returns a server TLS configuration using the reloader.
func (r *Reloader) Config() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: r.GetCertificate,
	}
}

// SelfSigned creates a throw-away ECDSA P-256 certificate valid for the given
// DNS names and IP addresses. The PEM of the certificate doubles as the CA
// bundle for the ValidatingWebhookConfiguration. It is meant for CI and local
// use: the key lives only in memory.
func SelfSigned(hosts []string, ttl time.Duration) (tls.Certificate, []byte, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, nil, errors.New("tls: at least one host is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kevgate-admit self-signed"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certPEM, nil
}
