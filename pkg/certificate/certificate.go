package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

type Handler struct{}

type Package struct {
	PublicCert []byte
	PrivateKey  *rsa.PrivateKey
}

func createTemplate() x509.Certificate {
	// Create a certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization: []string{"RPC-Go"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	return template
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) CreateCertificatePackage() (Package, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Package{}, err
	}

	template := createTemplate()

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return Package{}, err
	}

	pkg := Package{
		PublicCert: certDER,
		PrivateKey:  priv,
	}

	return pkg, nil
}
