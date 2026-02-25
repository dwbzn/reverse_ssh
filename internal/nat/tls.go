package nat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const quicALPN = "reverse_ssh/nat/1"

func serverTLSConfig(identity ed25519.PrivateKey) (*tls.Config, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "reverse_ssh_nat",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		identity.Public(),
		identity,
	)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(identity)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{quicALPN},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func clientTLSConfig(expected [32]byte) *tls.Config {
	return &tls.Config{
		NextProtos:         []string{quicALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Verified below against token key.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("unexpected peer key type %T", cert.PublicKey)
			}
			if len(pub) != len(expected) || !bytes.Equal(pub, expected[:]) {
				return fmt.Errorf("peer key mismatch")
			}
			return nil
		},
	}
}
