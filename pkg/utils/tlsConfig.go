package utils

import (
	"crypto/x509"
	"crypto/tls"
	"strings"
	log "github.com/sirupsen/logrus"
)

// CreateTLSConfig generates a TLS configuration based on the provided mode.
func CreateTLSConfig(currentMode int) *tls.Config {
	if currentMode == 0 { // Pre-provisioning mode
		return &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				allowedLeafCNs := []string{
					"AMT RCFG", "AMT AuditL", "AMT WS-MAN",
					"iAMT CSME IDevID RCFG", "iAMT CSME IDevID AuditL", "iAMT CSME IDevID WS-MAN",
				}

				allowedPrefixes := []string{
					"ODCA 2 CSME P", "ODCA 2 CSME", "On Die CSME", "On Die CSME P",
				}

				for i, rawCert := range rawCerts {
					cert, err := x509.ParseCertificate(rawCert)
					if err != nil {
						log.Error("Failed to parse certificate", i, ":", err)
						return err
					}

					if i == 0 { // Validate the leaf certificate
						if !isAllowedLeafCN(cert.Subject.CommonName, allowedLeafCNs) {
							log.Error("Leaf certificate CN is not allowed: ", cert.Subject.CommonName)
							return err
						}
					}

					if i == 3 { // Check the 4th certificate (CSME ROM ODCA Certificate)
						if !strings.Contains(cert.Subject.CommonName, "ROM CA") {
							log.Error("4th certificate Common Name does not contain 'ROM CA'")
							return err
						}

						ouFound := false
						for _, ou := range cert.Issuer.OrganizationalUnit {
							for _, prefix := range allowedPrefixes {
								if strings.Contains(ou, prefix) {
									log.Trace("Valid 4th certificate Issuer OU: ", ou)
									ouFound = true
									break
								}
							}
							if ouFound {
								break
							}
						}

						if !ouFound {
							log.Error("4th certificate Issuer OU does not contain a valid prefix")
							return err
						}
					}
				}

				return nil
			},
		}
	}

	// Default for ACM or CCM
	log.Info("Setting default TLS Config for ACM/CCM mode")
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