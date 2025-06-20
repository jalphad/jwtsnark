package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// GenerateSelfSignedCertAndKey creates a sample RSA private key and a self-signed X.509 certificate.
// In a real scenario, the JWT issuer generates these. The x5c field contains the certificate.
func GenerateSelfSignedCertAndKey(rsaBits int) (*rsa.PrivateKey, *x509.Certificate, []byte /*DER bytes*/, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "jwt-issuer.example.com",
			Organization: []string{"Example JWT Issuer"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, // Example usages
		BasicConstraintsValid: true,
		IsCA:                  false, // Not a CA certificate
	}

	// Create the certificate, signed by the private key itself (self-signed).
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return privKey, cert, derBytes, nil
}
