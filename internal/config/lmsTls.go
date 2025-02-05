/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strconv"

	"rpc/internal/amt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// CreateTLSConfig generates a TLS configuration based on the provided mode.
func GetTLSConfig(mode *int) *tls.Config {
	if *mode == 0 { // Pre-provisioning mode
		return &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				return verifyCertificates(rawCerts, mode)
			},
		}
	}
	// default tls config if device is in ACM or CCM
	log.Trace("Setting default TLS Config for ACM/CCM mode")
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func verifyCertificates(rawCerts [][]byte, mode *int) error {
	numCerts := len(rawCerts)
	const (
		selfSignedChainLength = 1
		prodChainLength       = 6
		lastIntermediateCert  = prodChainLength - 1
		odcaCertLevel         = 3
		leafLevel             = 0
	)
	if numCerts == prodChainLength {
		for i, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				log.Println("Failed to parse certificate", i, ":", err)
				return err
			}
			switch i {
			case leafLevel:
				if err := verifyLeafCertificate(cert.Subject.CommonName); err != nil {
					return err
				}
			case odcaCertLevel:
				if err := verifyROMODCACertificate(cert.Subject.CommonName, cert.Issuer.OrganizationalUnit); err != nil {
					return err
				}
			case lastIntermediateCert:
				if err := verifyLastIntermediateCert(cert); err != nil {
					return err
				}
			}
		}
		return nil
	} else if numCerts == selfSignedChainLength {
		return handleAMTTransition(mode)
	}
	return errors.New("unexpected number of certificates received from AMT: " + strconv.Itoa(numCerts))
}

// validate the leaf certificate
func verifyLeafCertificate(cn string) error {
	allowedLeafCNs := []string{
		"iAMT CSME IDevID RCFG", "AMT RCFG",
	}
	for _, allowed := range allowedLeafCNs {
		if cn == allowed {
			return nil
		}
	}
	log.Error("leaf certificate CN is not allowed: ", cn)
	return errors.New("leaf certificate CN is not allowed")
}

// validate CSME ROM ODCA certificate
func verifyROMODCACertificate(cn string, issuerOU []string) error {
	allowedOUPrefixes := []string{
		"ODCA 2 CSME P", "On Die CSME P", "ODCA 2 CSME", "On Die CSME",
	}

	if !strings.Contains(cn, "ROM CA") && !strings.Contains(cn, "ROM DE") {
		log.Error("invalid ROM ODCA Certificate: ", cn)
		return errors.New("invalid ROM ODCA Certificate")
	}

	// Check that OU of odcaCertLevel must have a prefix equal to either ODCA 2 CSME P or On Die CSME P
	for _, ou := range issuerOU {
		for _, prefix := range allowedOUPrefixes {
			if strings.HasPrefix(ou, prefix) {
				return nil
			}
		}
	}
	log.Error("ROM ODCA Certificate OU does not have a valid prefix: ", issuerOU)
	return errors.New("ROM ODCA Certificate OU does not have a valid prefix")
}

// check if the last intermediate cert is signed by trusted root certificate
func verifyLastIntermediateCert(cert *x509.Certificate) error {
	// Base64 encoded DER certificate without line breaks ttps://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
	const certBase64 = `MIICujCCAj6gAwIBAgIUPLLiHTrwySRtWxR4lxKLlu7MJ7wwDAYIKoZIzj0EAwMFADCBiTELMAkGA1UEBgwCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xIzAhBgNVBAsMGk9uRGllIENBIFJvb3QgQ2VydCBTaWduaW5nMRYwFAYDVQQDDA13d3cuaW50ZWwuY29tMB4XDTE5MDQwMzAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowgYkxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSMwIQYDVQQLDBpPbkRpZSBDQSBSb290IENlcnQgU2lnbmluZzEWMBQGA1UEAwwNd3d3LmludGVsLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK8SfB2UflvXZqb5Kc3+lokrABHWazvNER2axPURP64HILkXChPB0OEX5hLB7Okw7Dy6oFqB5tQVDupgfvUX/SgYBEaDdG5rCVFrGAis6HX5TA2ewQmj14r2ncHBgnppB6NjMGEwHwYDVR0jBBgwFoAUtFjJ9uQIQKPyWMg5eG6ujgqNnDgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFLRYyfbkCECj8ljIOXhuro4KjZw4MAwGCCqGSM49BAMDBQADaAAwZQIxAP9B4lFF86uvpHmkcp61cWaU565ayE3p7ezu9haLE/lPLh5hFQfmTi1nm/sG3JEXMQIwNpKfHoDmUTrUyezhhfv3GG+1CqBXstmCYH40buj9jKW3pHWc71s9arEmPWli7I8U`
	// Decode the Base64 certificate string
	certBytes, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		log.Error("Failed to decode base64 certificate: ", err)
		return err
	}
	// Parse the DER certificate into an x509.Certificate
	prodRootCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Error("Failed to parse root certificate: ", err)
		return err
	}
	err = cert.CheckSignatureFrom(prodRootCert)
	if err != nil {
		log.Error("last certificate in the chain is not signed by a trusted root certificate: ", err)
		return err
	}
	return nil
}

// handleAMTTransition checks if AMT has moved from Pre-Provisioning mode.
func handleAMTTransition(mode *int) error {
	controlMode, err := amt.NewAMTCommand().GetControlMode()
	if err != nil {
		log.Error("Failed to get control mode: ", err)
		return err
	}
	if controlMode != 0 {
		log.Trace("AMT has transitioned to mode: ", controlMode)
		*mode = controlMode
		return nil
	}
	log.Error("unexpected number of certificates received from AMT")
	return errors.New("unexpected number of certificates received from AMT")
}
