/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"rpc/internal/certs"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Helper function to create test certificates with proper chain of trust
func createTestCert(t *testing.T, template *x509.Certificate, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// If no parent is provided, create a self-signed certificate
	if parent == nil {
		parent = template
		parentKey = privateKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

func createCertTemplate(commonName string, isCA bool, ou []string) *x509.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: ou,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
}

func TestGetTLSConfig(t *testing.T) {
	mode := 0
	tlsConfig := GetTLSConfig(&mode)
	assert.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.InsecureSkipVerify)
	assert.NotNil(t, tlsConfig.VerifyPeerCertificate)

	mode = 1
	tlsConfig = GetTLSConfig(&mode)
	assert.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.InsecureSkipVerify)
	assert.Nil(t, tlsConfig.VerifyPeerCertificate)
}

func TestVerifyLeafCertificate(t *testing.T) {
	tests := []struct {
		cn        string
		shouldErr bool
	}{
		{"iAMT CSME IDevID RCFG", false},
		{"AMT RCFG", false},
		{"Invalid CN", true},
	}

	for _, tt := range tests {
		err := VerifyLeafCertificate(tt.cn)
		if tt.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestVerifyROMODCACertificate(t *testing.T) {
	tests := []struct {
		cn        string
		issuerOU  []string
		shouldErr bool
	}{
		{"ROM CA Cert", []string{"ODCA 2 CSME P"}, false},
		{"ROM DE Cert", []string{"On Die CSME P"}, false},
		{"Invalid Cert", []string{"Invalid OU"}, true},
	}

	for _, tt := range tests {
		err := VerifyROMODCACertificate(tt.cn, tt.issuerOU)
		if tt.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestVerifyLastIntermediateCert(t *testing.T) {
	mockCert := &x509.Certificate{}
	err := VerifyLastIntermediateCert(mockCert)
	assert.Error(t, err) // Expecting error as mock cert won't be signed by a trusted root
}

func TestVerifyCertificates(t *testing.T) {
	// Create the root certificate (7th certificate, used for verification)
	rootTemplate := createCertTemplate("Intel Root CA", true, []string{"Intel Root OU"})
	rootCert, rootKey := createTestCert(t, rootTemplate, nil, nil)

	// Create the last intermediate certificate (6th in chain)
	lastIntermTemplate := createCertTemplate("Last Intermediate CA", true, []string{"Last Intermediate OU"})
	lastIntermCert, lastIntermKey := createTestCert(t, lastIntermTemplate, rootCert, rootKey)

	// Create the 5th certificate
	interm5Template := createCertTemplate("Intermediate CA 5", true, []string{"ODCA 2 CSME P"})
	interm5Cert, interm5Key := createTestCert(t, interm5Template, lastIntermCert, lastIntermKey)

	// Create the ODCA certificate (4th in chain)
	odcaTemplate := createCertTemplate("ROM CA", true, []string{"Intermediate 4 OU"})
	odcaCert, odcaKey := createTestCert(t, odcaTemplate, interm5Cert, interm5Key)

	// Create the 3rd certificate
	interm3Template := createCertTemplate("Intermediate CA 3", true, []string{"Intermediate 3 OU"})
	interm3Cert, interm3Key := createTestCert(t, interm3Template, odcaCert, odcaKey)

	// Create the 2nd certificate
	interm2Template := createCertTemplate("Intermediate CA 2", true, []string{"Intermediate 2 OU"})
	interm2Cert, interm2Key := createTestCert(t, interm2Template, interm3Cert, interm3Key)

	// Create the leaf certificate (1st in chain)
	leafTemplate := createCertTemplate("iAMT CSME IDevID RCFG", false, []string{"Leaf OU"})
	leafCert, _ := createTestCert(t, leafTemplate, interm2Cert, interm2Key)

	tests := []struct {
		name     string
		rawCerts [][]byte
		mode     int
		wantErr  bool
	}{
		{
			name: "Valid production chain",
			rawCerts: [][]byte{
				leafCert.Raw,       // 1st - Leaf certificate
				interm2Cert.Raw,    // 2nd - Intermediate certificate
				interm3Cert.Raw,    // 3rd - Intermediate certificate
				odcaCert.Raw,       // 4th - ODCA certificate
				interm5Cert.Raw,    // 5th - Intermediate certificate
				lastIntermCert.Raw, // 6th - Last intermediate certificate
			},
			mode:    0,
			wantErr: false,
		},
		{
			name: "Invalid chain length",
			rawCerts: [][]byte{
				leafCert.Raw,
				interm2Cert.Raw,
			},
			mode:    0,
			wantErr: true,
		},
	}
	// Mock the root certificate for verification
	certs.OnDie_CA_RootCA_Certificate = rootCert.Raw
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificates(tt.rawCerts, &tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyCertificates() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
