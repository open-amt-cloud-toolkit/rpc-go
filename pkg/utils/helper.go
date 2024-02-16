/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

func InterpretControlMode(mode int) string {
	switch mode {
	case 0:
		return "pre-provisioning state"
	case 1:
		return "activated in client control mode"
	case 2:
		return "activated in admin control mode"
	default:
		return "unknown state"
	}
}

func InterpretProvisioningState(state int) string {
	switch state {
	case 0:
		return "pre-provisioning state"
	case 1:
		return "in-provisioning state"
	case 2:
		return "post-provisioning state"
	default:
		return "unknown state"
	}
}

func InterpretHashAlgorithm(hashAlgorithm int) (hashSize int, algorithm string) {
	switch hashAlgorithm {
	case 0: // MD5
		hashSize = 16
		algorithm = "MD5"
	case 1: // SHA1
		hashSize = 20
		algorithm = "SHA1"
	case 2: // SHA256
		hashSize = 32
		algorithm = "SHA256"
	case 3: // SHA512
		hashSize = 64
		algorithm = "SHA512"
	default:
		hashSize = 0
		algorithm = "UNKNOWN"
	}
	return
}

func InterpretAMTNetworkConnectionStatus(status int) string {
	switch status {
	case 0:
		return "direct"
	case 1:
		return "vpn"
	case 2:
		return "outside enterprise"
	default:
		return "unknown"
	}
}
func InterpretRemoteAccessConnectionStatus(status int) string {
	switch status {
	case 0:
		return "not connected"
	case 1:
		return "connecting"
	case 2:
		return "connected"
	default:
		return "unknown"
	}
}
func InterpretRemoteAccessTrigger(status int) string {
	switch status {
	case 0:
		return "user initiated"
	case 1:
		return "alert"
	case 2:
		return "periodic"
	case 3:
		return "provisioning"
	default:
		return "unknown"
	}
}
func GenerateCertificate() (cert *x509.Certificate, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Open AMT Cloud Toolkit"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},              
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")}, 
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
