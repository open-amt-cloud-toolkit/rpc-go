package certtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

type TestCerts struct {
	CaCert        x509.Certificate
	CaPem         string
	CaFingerprint string
	InterCert     x509.Certificate
	InterPem      string
	LeafCert      x509.Certificate
	LeafPem       string
	PfxData       []byte
	Pfxb64        string
	PfxPassword   string
}

func New(password string) *TestCerts {
	tc := &TestCerts{}
	tc.CaCert = x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA, INC."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
		return tc
	}
	tc.CaCert.Raw, err = x509.CreateCertificate(rand.Reader, &tc.CaCert, &tc.CaCert, &caKey.PublicKey, caKey)
	if err != nil {
		fmt.Println(err)
		return tc
	}
	hash := sha256.Sum256(tc.CaCert.Raw)
	tc.CaFingerprint = hex.EncodeToString(hash[:])
	tc.CaPem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.CaCert.Raw}))

	tc.InterCert = x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			Organization: []string{"Test Intermediate CA, INC."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	interKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
		return tc
	}
	tc.InterCert.Raw, err = x509.CreateCertificate(rand.Reader, &tc.InterCert, &tc.CaCert, &interKey.PublicKey, caKey)
	if err != nil {
		fmt.Println(err)
		return tc
	}
	tc.InterPem = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tc.InterCert.Raw,
	}))

	tc.LeafCert = x509.Certificate{
		SerialNumber: big.NewInt(3000),
		Subject: pkix.Name{
			Organization: []string{"Test Server Cert, INC."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
		return tc
	}
	tc.LeafCert.Raw, err = x509.CreateCertificate(rand.Reader, &tc.LeafCert, &tc.InterCert, &leafKey.PublicKey, interKey)
	if err != nil {
		fmt.Println(err)
		return tc
	}
	tc.LeafPem = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tc.LeafCert.Raw,
	}))

	tc.PfxPassword = password
	tc.PfxData, err = pkcs12.Encode(rand.Reader, leafKey, &tc.LeafCert, []*x509.Certificate{&tc.InterCert, &tc.CaCert}, tc.PfxPassword)
	tc.Pfxb64 = base64.StdEncoding.EncodeToString(tc.PfxData)
	return tc
}
