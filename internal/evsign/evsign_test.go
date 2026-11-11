package evsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

const (
	dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var report = []byte(`{"SchemaVersion":2,"Results":[]}`)

func keypair(t *testing.T, kind Kind) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := GenerateKey(kind)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func signWith(t *testing.T, priv []byte, digest string, rep []byte) []byte {
	t.Helper()
	k, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(k, digest, rep)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, kind := range []Kind{Ed25519, ECDSA} {
		t.Run(string(kind), func(t *testing.T) {
			priv, pub := keypair(t, kind)
			v, err := NewVerifier(pub)
			if err != nil {
				t.Fatal(err)
			}
			sig := signWith(t, priv, dA, report)
			if err := v.Verify(dA, report, sig); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			if !bytes.HasSuffix(sig, []byte("\n")) {
				t.Error("signature file has no trailing newline")
			}
			// CRLF or surrounding whitespace in the .sig file is tolerated.
			if err := v.Verify(dA, report, []byte("  "+strings.TrimSpace(string(sig))+"\r\n")); err != nil {
				t.Errorf("whitespace around the signature rejected: %v", err)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	for _, kind := range []Kind{Ed25519, ECDSA} {
		t.Run(string(kind), func(t *testing.T) {
			priv, pub := keypair(t, kind)
			_, otherPub := keypair(t, kind)
			_, otherKindPub := keypair(t, map[Kind]Kind{Ed25519: ECDSA, ECDSA: Ed25519}[kind])
			v, _ := NewVerifier(pub)
			good := signWith(t, priv, dA, report)

			tampered := bytes.Replace(report, []byte("Results"), []byte("Resultz"), 1)
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(good)))
			flipped := append([]byte(nil), raw...)
			flipped[len(flipped)/2] ^= 1

			tests := []struct {
				name   string
				verify func() error
			}{
				{"tampered report", func() error { return v.Verify(dA, tampered, good) }},
				{"appended byte", func() error { return v.Verify(dA, append(append([]byte(nil), report...), ' '), good) }},
				{"replayed under another digest", func() error { return v.Verify(dB, report, good) }},
				{"flipped signature bit", func() error {
					return v.Verify(dA, report, []byte(base64.StdEncoding.EncodeToString(flipped)))
				}},
				{"truncated signature", func() error {
					return v.Verify(dA, report, []byte(base64.StdEncoding.EncodeToString(raw[:len(raw)-1])))
				}},
				{"wrong key", func() error {
					w, _ := NewVerifier(otherPub)
					return w.Verify(dA, report, good)
				}},
				{"key of the other type", func() error {
					w, _ := NewVerifier(otherKindPub)
					return w.Verify(dA, report, good)
				}},
				{"empty signature file", func() error { return v.Verify(dA, report, nil) }},
				{"not base64", func() error { return v.Verify(dA, report, []byte("%%%not base64%%%")) }},
				{"oversize signature file", func() error { return v.Verify(dA, report, bytes.Repeat([]byte("A"), MaxSignatureFileBytes+1)) }},
				{"signature over the bare report without the digest", func() error {
					// what a plain `openssl dgst -sign` over the file would produce
					k, _ := ParsePrivateKey(priv)
					var sig []byte
					if ek, ok := k.(*ecdsa.PrivateKey); ok {
						sig, _ = ecdsa.SignASN1(rand.Reader, ek, report)
					} else {
						sig = ed25519.Sign(k.(ed25519.PrivateKey), report)
					}
					return v.Verify(dA, report, []byte(base64.StdEncoding.EncodeToString(sig)))
				}},
			}
			for _, tc := range tests {
				err := tc.verify()
				if err == nil {
					t.Errorf("%s: verified", tc.name)
				} else if !errors.Is(err, ErrInvalid) {
					t.Errorf("%s: error %v does not wrap ErrInvalid", tc.name, err)
				}
			}
		})
	}
}

func TestKeyRotationAcceptsAnyTrustedKey(t *testing.T) {
	oldPriv, oldPub := keypair(t, Ed25519)
	newPriv, newPub := keypair(t, ECDSA)
	_, strangerPub := keypair(t, Ed25519)
	v, err := NewVerifier(append(append(append([]byte(nil), oldPub...), newPub...), strangerPub...))
	if err != nil {
		t.Fatal(err)
	}
	if v.Keys() != 3 {
		t.Fatalf("keys = %d", v.Keys())
	}
	for _, p := range [][]byte{oldPriv, newPriv} {
		if err := v.Verify(dA, report, signWith(t, p, dA, report)); err != nil {
			t.Errorf("trusted key rejected: %v", err)
		}
	}
}

func TestNewVerifierRejectsBadKeys(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	_, pub := keypair(t, Ed25519)
	enc := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"garbage", []byte("not pem")},
		{"rsa", enc("PUBLIC KEY", rsaDER)},
		{"p384", enc("PUBLIC KEY", p384DER)},
		{"wrong block type", enc("CERTIFICATE", []byte("x"))},
		{"private key block", enc("PRIVATE KEY", []byte("x"))},
		{"corrupt der", enc("PUBLIC KEY", []byte("nope"))},
		{"trailing garbage", append(append([]byte(nil), pub...), []byte("junk")...)},
		{"too many keys", bytes.Repeat(pub, maxKeys+1)},
	}
	for _, tc := range tests {
		if v, err := NewVerifier(tc.in); err == nil {
			t.Errorf("%s: accepted (%d keys)", tc.name, v.Keys())
		}
	}
}

func TestParsePrivateKeyRejects(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKCS8PrivateKey(p384)
	_, pub := keypair(t, Ed25519)
	for name, in := range map[string][]byte{
		"empty":      nil,
		"public key": pub,
		"rsa":        pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}),
		"p384":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384DER}),
		"corrupt":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
	} {
		if _, err := ParsePrivateKey(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := GenerateKey("rsa"); err == nil {
		t.Error("GenerateKey accepted an unknown kind")
	}
}
