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
				const (
					prodChainLength       = 6
					selfSignedChainLength = 1
				)
				if len(rawCerts) == prodChainLength {
					allowedLeafCNs := []string{
						"iAMT-RCFG", "iAMT CSME IDevID RCFG", "AMT RCFG",
					}
					allowedOUPrefixes := []string{
						"ODCA 2 CSME P", "On Die CSME P", "ODCA 2 CSME", "On Die CSME",
					}
					const (
						leafLevel     = 0
						odcaCertLevel = 3
						rootLevel     = 5
					)
					for i, rawCert := range rawCerts {
						cert, err := x509.ParseCertificate(rawCert)
						if err != nil {
							log.Error("Failed to parse certificate", i, ":", err)
							return err
						}
						// log.Tracef("Subject: %s, Issuer: %s, Serial Number: %s, Not Before: %s, Not After: %s", cert.Subject, cert.Issuer, cert.SerialNumber, cert.NotBefore, cert.NotAfter)
						// Validate the leaf certificate
						if i == leafLevel {
							if !isAllowedLeafCN(cert.Subject.CommonName, allowedLeafCNs) {
								log.Error("Leaf certificate CN is not allowed: ", cert.Subject.CommonName)
								return errors.New("leaf certificate CN is not allowed: " + cert.Subject.CommonName)
							}
						}
						// Validate 4th certificate (CSME ROM ODCA Certificate)
						if i == odcaCertLevel {
							if !strings.Contains(cert.Subject.CommonName, "ROM CA") {
								log.Error("4th certificate Common Name does not contain 'ROM CA'")
								return errors.New("4th certificate Common Name does not contain 'ROM CA'")
							}
							// Check that organizationalUnitName Attribute (OU) of odcaCertLevel must have a prefix equal to either ODCA 2 CSME P or On Die CSME P
							validOU := false
							for _, ou := range cert.Issuer.OrganizationalUnit {
								for _, prefix := range allowedOUPrefixes {
									if strings.HasPrefix(ou, prefix) {
										validOU = true
										break
									}
								}
								if validOU {
									break
								}
							}
							if !validOU {
								log.Error("4th certificate Organizational Unit does not have a valid prefix")
								return errors.New("4th certificate Organizational Unit does not have a valid prefix")
							}
							// TODO: Check system UPID matches with first 20 bytes of sha256 hash of the 4th certificate
						}
						// check if last intermediate certificate is not signed by trusted root certificate
						if i == rootLevel {
							// Base64 encoded DER certificate without line breaks ttps://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
							certBase64 := `MIICujCCAj6gAwIBAgIUPLLiHTrwySRtWxR4lxKLlu7MJ7wwDAYIKoZIzj0EAwMFADCBiTELMAkGA1UEBgwCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xIzAhBgNVBAsMGk9uRGllIENBIFJvb3QgQ2VydCBTaWduaW5nMRYwFAYDVQQDDA13d3cuaW50ZWwuY29tMB4XDTE5MDQwMzAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowgYkxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSMwIQYDVQQLDBpPbkRpZSBDQSBSb290IENlcnQgU2lnbmluZzEWMBQGA1UEAwwNd3d3LmludGVsLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK8SfB2UflvXZqb5Kc3+lokrABHWazvNER2axPURP64HILkXChPB0OEX5hLB7Okw7Dy6oFqB5tQVDupgfvUX/SgYBEaDdG5rCVFrGAis6HX5TA2ewQmj14r2ncHBgnppB6NjMGEwHwYDVR0jBBgwFoAUtFjJ9uQIQKPyWMg5eG6ujgqNnDgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFLRYyfbkCECj8ljIOXhuro4KjZw4MAwGCCqGSM49BAMDBQADaAAwZQIxAP9B4lFF86uvpHmkcp61cWaU565ayE3p7ezu9haLE/lPLh5hFQfmTi1nm/sG3JEXMQIwNpKfHoDmUTrUyezhhfv3GG+1CqBXstmCYH40buj9jKW3pHWc71s9arEmPWli7I8U`
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
						}
						// TODO: check CRL for each certificate in the chain
					}
				} else if len(rawCerts) == selfSignedChainLength { // this is for the scenario where AMT transitions from Preprovisioning mode to ACM/CCM
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
				} else {
					return errors.New("unexpected number of certificates received from AMT: " + strconv.Itoa(len(rawCerts)))
				}
				return nil
			},
		}
	}

	// Default for ACM or CCM
	log.Trace("Setting default TLS Config for ACM/CCM mode")
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func isAllowedLeafCN(cn string, allowedCNs []string) bool {
	for _, allowed := range allowedCNs {
		if cn == allowed {
			return true
		}
	}
	return false
}
