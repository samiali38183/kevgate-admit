// Package evsign signs and verifies scan reports with detached signatures.
//
// A report named sha256-<hex>.json has its signature in sha256-<hex>.json.sig.
// The signature covers the report bytes AND the image digest the report is
// stored for, so a validly signed report cannot be copied under another
// digest's file name and replayed for a different image:
//
//	message = "kevgate-admit report signature v1\n" || digest || "\n" || report
//
// Keys are PKIX public keys (PEM "PUBLIC KEY"): Ed25519, or ECDSA on P-256.
// Ed25519 signs the message directly; ECDSA signs SHA-256(message) and the
// signature is ASN.1 DER. The .sig file holds the base64 of the signature.
//
// This authenticates who wrote a report into the store. It says nothing about
// the image itself and is not an image signature check.
package evsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Suffix is appended to a report file name to get its signature file name.
const Suffix = ".sig"

// MaxSignatureFileBytes bounds a signature file; real ones are under 200 bytes.
const MaxSignatureFileBytes = 4096

const (
	domainSeparator = "kevgate-admit report signature v1\n"
	maxKeys         = 8
)

// ErrInvalid means the signature does not verify against any trusted key, or
// is malformed.
var ErrInvalid = errors.New("invalid report signature")

// Message builds the byte string that is signed.
func Message(digest string, report []byte) []byte {
	m := make([]byte, 0, len(domainSeparator)+len(digest)+1+len(report))
	m = append(m, domainSeparator...)
	m = append(m, digest...)
	m = append(m, '\n')
	return append(m, report...)
}

// Kind names a supported key type.
type Kind string

// Supported key types.
const (
	Ed25519 Kind = "ed25519"
	ECDSA   Kind = "ecdsa"
)

// GenerateKey returns a new key pair as PEM (PKCS#8 private, PKIX public).
func GenerateKey(kind Kind) (privPEM, pubPEM []byte, err error) {
	var priv crypto.Signer
	switch kind {
	case Ed25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case ECDSA:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("evsign: unknown key type %q (use ed25519 or ecdsa)", kind)
	}
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), nil
}

// ParsePrivateKey reads one PKCS#8 PEM private key (Ed25519 or ECDSA P-256).
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("evsign: private key must be a PEM PRIVATE KEY (PKCS#8) block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("evsign: private key: %w", err)
	}
	switch v := k.(type) {
	case ed25519.PrivateKey:
		return v, nil
	case *ecdsa.PrivateKey:
		if v.Curve == elliptic.P256() {
			return v, nil
		}
	}
	return nil, errors.New("evsign: unsupported private key type (use Ed25519 or ECDSA P-256)")
}

// Sign returns the base64 signature file content for a report.
func Sign(key crypto.Signer, digest string, report []byte) ([]byte, error) {
	msg := Message(digest, report)
	var sig []byte
	var err error
	switch key.(type) {
	case ed25519.PrivateKey:
		sig, err = key.Sign(rand.Reader, msg, crypto.Hash(0))
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256(msg)
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
	default:
		return nil, errors.New("evsign: unsupported key type")
	}
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n"), nil
}

// Verifier checks signatures against a fixed set of trusted public keys. A
// signature by any of them is accepted, which allows key rotation.
type Verifier struct {
	keys []crypto.PublicKey
}

// NewVerifier parses one or more PEM PUBLIC KEY blocks.
func NewVerifier(pemData []byte) (*Verifier, error) {
	v := &Verifier{}
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("evsign: unexpected PEM block %q (want PUBLIC KEY)", block.Type)
		}
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("evsign: public key: %w", err)
		}
		switch pk := k.(type) {
		case ed25519.PublicKey:
			v.keys = append(v.keys, pk)
		case *ecdsa.PublicKey:
			if pk.Curve != elliptic.P256() {
				return nil, errors.New("evsign: only ECDSA P-256 keys are supported")
			}
			v.keys = append(v.keys, pk)
		default:
			return nil, errors.New("evsign: unsupported public key type (use Ed25519 or ECDSA P-256)")
		}
		if len(v.keys) > maxKeys {
			return nil, fmt.Errorf("evsign: more than %d public keys", maxKeys)
		}
	}
	if len(v.keys) == 0 {
		return nil, errors.New("evsign: no PEM PUBLIC KEY block found")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("evsign: unexpected data after the last PEM block")
	}
	return v, nil
}

// Keys returns how many trusted keys are loaded.
func (v *Verifier) Keys() int { return len(v.keys) }

// Verify checks sigFile (the content of the .sig file) for the report stored
// under digest. Every failure wraps ErrInvalid.
func (v *Verifier) Verify(digest string, report, sigFile []byte) error {
	if len(sigFile) > MaxSignatureFileBytes {
		return fmt.Errorf("%w: signature file too large", ErrInvalid)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigFile)))
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("%w: signature is not valid base64", ErrInvalid)
	}
	msg := Message(digest, report)
	sum := sha256.Sum256(msg)
	for _, k := range v.keys {
		switch pk := k.(type) {
		case ed25519.PublicKey:
			if ed25519.Verify(pk, msg, sig) {
				return nil
			}
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pk, sum[:], sig) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: no trusted key verifies it", ErrInvalid)
}
