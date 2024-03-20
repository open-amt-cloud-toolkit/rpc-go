package local

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"rpc/pkg/utils"
	"strings"

	log "github.com/sirupsen/logrus"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func (service *ProvisioningService) Activate() error {

	controlMode, err := service.amtCommand.GetControlMode()
	if err != nil {
		return utils.AMTConnectionFailed
	}
	if controlMode != 0 {
		log.Error("Device is already activated")
		return utils.UnableToActivate
	}

	service.CheckAndEnableAMT(service.flags.SkipIPRenew)
	amtVersion, err := service.amtCommand.GetVersionDataFromME("AMT", service.flags.AMTTimeoutDuration)
	if err != nil {
		return utils.AMTConnectionFailed
	}
	amtMajorVersion := GetAMTMajorVersion(amtVersion)
	if amtMajorVersion > 14 {
		log.Info("AMT version 15 or greater detected, using secure host based configuration flow")
		service.flags.UseTLSActivation = true
	}

	// for local activation, wsman client needs local system account credentials
	lsa, err := service.amtCommand.GetLocalSystemAccount()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}

	// Need to get certificate from AMT and pass it into the SetupWsmanClient
	if service.flags.UseTLSActivation {
		response, certificate, err := service.amtCommand.StartTLSActivation()
		if err != nil {
			log.Error(err)
			return utils.AMTConnectionFailed
		}
		fmt.Println(response)
		fmt.Println(certificate)
		log.Debug("Secure Configuration: command: ", response.Header.Status)
		service.flags.AMTTLSActivationCertificateHash = response.AMTCertHash[:]
		service.flags.RPCTLSActivationCertificate = certificate
		service.interfacedWsmanMessage.SetupWsmanClient(lsa.Username, lsa.Password, log.GetLevel() == log.TraceLevel, []tls.Certificate{service.flags.RPCTLSActivationCertificate.TlsCert})
		if service.flags.UseACM {
			err = service.ActivateACMOverTLS()
			if err == nil {
				log.Info("Status: Device activated in Admin Control Mode")
			}
		} else if service.flags.UseCCM {
			err = service.ActivateCCMOverTLS()
			if err == nil {
				log.Info("Status: Device activated in Client Control Mode")
			}
		}
	} else {
		service.interfacedWsmanMessage.SetupWsmanClient(lsa.Username, lsa.Password, log.GetLevel() == log.TraceLevel, []tls.Certificate{})
		if service.flags.UseACM {
			err = service.ActivateACMOverNonTLS()
			if err == nil {
				log.Info("Status: Device activated in Admin Control Mode")
			}
		} else if service.flags.UseCCM {
			err = service.ActivateCCMOverNonTLS()
		}
	}

	return err
}

func (service *ProvisioningService) ActivateACMOverNonTLS() error {
	// Extract the provisioning certificate
	certObject, fingerPrint, err := service.GetProvisioningCertObj()
	if err != nil {
		return utils.ActivationFailed
	}
	// Check provisioning certificate is accepted by AMT
	err = service.CompareCertHashes(fingerPrint)
	if err != nil {
		return utils.ActivationFailed
	}

	generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
	if err != nil {
		return utils.ActivationFailed
	}

	getHostBasedSetupResponse, err := service.interfacedWsmanMessage.GetHostBasedSetupService()
	if err != nil {
		return utils.ActivationFailed
	}
	decodedNonce := getHostBasedSetupResponse.Body.GetResponse.ConfigurationNonce
	fwNonce, err := base64.StdEncoding.DecodeString(decodedNonce)
	if err != nil {
		return utils.ActivationFailed
	}

	err = service.injectCertificate(certObject.certChain)
	if err != nil {
		return utils.ActivationFailed
	}

	nonce, err := service.generateNonce()
	if err != nil {
		return utils.ActivationFailed
	}

	signedSignature, err := service.createSignedString(nonce, fwNonce, certObject.privateKey)
	if err != nil {
		return utils.ActivationFailed
	}

	_, err = service.interfacedWsmanMessage.HostBasedSetupServiceAdmin(service.config.ACMSettings.AMTPassword, generalSettings.Body.GetResponse.DigestRealm, nonce, signedSignature)
	if err != nil {
		controlMode, err := service.amtCommand.GetControlMode()
		if err != nil {
			return utils.AMTConnectionFailed
		}
		if controlMode != 2 {
			return utils.ActivationFailed
		}
		return nil
	}
	return nil
}

func (service *ProvisioningService) ActivateACMOverTLS() error {
	// TODO: fill this shit in

	return nil
}

func (service *ProvisioningService) ActivateCCMOverNonTLS() error {
	generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
	if err != nil {
		return utils.ActivationFailed
	}
	_, err = service.interfacedWsmanMessage.HostBasedSetupService(generalSettings.Body.GetResponse.DigestRealm, service.config.Password)
	if err != nil {
		if service.flags.UseTLSActivation {
			response, _ := service.amtCommand.StopTLSActivation()
			if response.Header.Status == 0 {
				log.Info("Secure Configuration stopped")
			}
		}
		return utils.ActivationFailed
	}
	log.Info("Status: Device activated in Client Control Mode")
	return nil
}

func (service *ProvisioningService) ActivateCCMOverTLS() error {

	log.Info("Secure Configuration started")
	mode, err := service.amtCommand.GetProvisioningState()
	if err != nil {
		log.Error(err)
	}
	log.Debug("AMT mode: ", string(utils.InterpretProvisioningState(mode)))
	resp1, err := service.interfacedWsmanMessage.SetAdminPassword("admin", service.flags.Password)
	if err != nil {
		log.Error(err)
		return utils.ActivationFailed
	}
	log.Info(resp1)
	resp2, err := service.interfacedWsmanMessage.SetupMEBX("P@ssw0rd")
	if err != nil {
		log.Error(err)
		return utils.ActivationFailed
	}
	log.Info(resp2)
	resp3, err := service.interfacedWsmanMessage.CommitChanges()
	if err != nil {
		log.Error(err)
		return utils.ActivationFailed
	}
	log.Info(resp3)
	return nil
}

type CertsAndKeys struct {
	certs []*x509.Certificate
	keys  []interface{}
}

type CertificateObject struct {
	pem     string
	subject string
	issuer  string
}

type ProvisioningCertObj struct {
	certChain  []string
	privateKey crypto.PrivateKey
}

func cleanPEM(pem string) string {
	pem = strings.Replace(pem, "-----BEGIN CERTIFICATE-----", "", -1)
	pem = strings.Replace(pem, "-----END CERTIFICATE-----", "", -1)
	return strings.Replace(pem, "\n", "", -1)
}

func (service *ProvisioningService) GetProvisioningCertObj() (ProvisioningCertObj, string, error) {
	config := service.config.ACMSettings
	certsAndKeys, err := convertPfxToObject(config.ProvisioningCert, config.ProvisioningCertPwd)
	if err != nil {
		return ProvisioningCertObj{}, "", err
	}
	result, fingerprint, err := dumpPfx(certsAndKeys)
	if err != nil {
		return ProvisioningCertObj{}, "", err
	}
	return result, fingerprint, nil
}

func convertPfxToObject(pfxb64 string, passphrase string) (CertsAndKeys, error) {
	pfx, err := base64.StdEncoding.DecodeString(pfxb64)
	if err != nil {
		return CertsAndKeys{}, err
	}
	privateKey, certificate, extraCerts, err := pkcs12.DecodeChain(pfx, passphrase)
	if err != nil {
		return CertsAndKeys{}, errors.New("decrypting provisioning certificate failed")
	}
	certs := append([]*x509.Certificate{certificate}, extraCerts...)
	pfxOut := CertsAndKeys{certs: certs, keys: []interface{}{privateKey}}

	return pfxOut, nil
}

func dumpPfx(pfxobj CertsAndKeys) (ProvisioningCertObj, string, error) {
	if len(pfxobj.certs) == 0 {
		return ProvisioningCertObj{}, "", errors.New("no certificates found")
	}
	if len(pfxobj.keys) == 0 {
		return ProvisioningCertObj{}, "", errors.New("no private keys found")
	}
	var provisioningCertificateObj ProvisioningCertObj
	var certificateList []*CertificateObject
	var fingerprint string

	for _, cert := range pfxobj.certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		pem := cleanPEM(string(pem.EncodeToMemory(pemBlock)))
		certificateObject := CertificateObject{pem: pem, subject: cert.Subject.String(), issuer: cert.Issuer.String()}

		// Get the fingerpint from the Root certificate
		if cert.Subject.String() == cert.Issuer.String() {
			der := cert.Raw
			hash := sha256.Sum256(der)
			fingerprint = hex.EncodeToString(hash[:])
		}

		// Put all the certificateObjects into a single un-ordered list
		certificateList = append(certificateList, &certificateObject)
	}

	// Order the certificates from leaf to root
	orderedCertificateList := orderCertificates(certificateList)

	// Add them to the certChain in order
	for _, cert := range orderedCertificateList {
		provisioningCertificateObj.certChain = append(provisioningCertificateObj.certChain, cert.pem)
	}

	// Add the priviate key
	provisioningCertificateObj.privateKey = pfxobj.keys[0]

	return provisioningCertificateObj, fingerprint, nil
}

// orderCertificates orders the certificate list from leaf to root
func orderCertificates(certificates []*CertificateObject) []*CertificateObject {

	// create a map that we'll use to get the next certificate in chain
	certificateMap := make(map[string]*CertificateObject)
	for _, cert := range certificates {
		certificateMap[cert.subject] = cert
	}

	// this slice will hold our ordered certificates
	orderedCertificates := []*CertificateObject{}

	// Set current to the leaf certificate since it is always first in our list
	current := certificateMap[certificates[0].subject]

	// Loop through certificate list until we get to root certificate
	for current != nil && current.issuer != current.subject {
		// Append current certificate to the ordered list
		orderedCertificates = append(orderedCertificates, current)
		// Move to the issuer of the current certificate
		current = certificateMap[current.issuer]
	}

	// Append the root certificate
	if current != nil {
		orderedCertificates = append(orderedCertificates, current)
	}

	return orderedCertificates
}

func (service *ProvisioningService) CompareCertHashes(fingerPrint string) error {
	result, err := service.amtCommand.GetCertificateHashes()
	if err != nil {
		log.Error(err)
	}
	for _, v := range result {
		if v.Hash == fingerPrint {
			return nil
		}
	}
	return errors.New("the root of the provisioning certificate does not match any of the trusted roots in AMT")
}

func (service *ProvisioningService) injectCertificate(certChain []string) error {
	firstIndex := 0
	lastIndex := len(certChain) - 1
	for i, cert := range certChain {
		isLeaf := i == firstIndex
		isRoot := i == lastIndex

		_, err := service.interfacedWsmanMessage.AddNextCertInChain(cert, isLeaf, isRoot)
		if err != nil {
			log.Error(err)
			// TODO: check if this is the correct error to return
			return errors.New("failed to add certificate to AMT")
		}
	}
	return nil
}

func (service *ProvisioningService) generateNonce() ([]byte, error) {
	nonce := make([]byte, 20)
	// fills nonce with 20 random bytes
	if _, err := rand.Read(nonce); err != nil {
		log.Error("Error generating nonce:", err)
		return nil, err
	}
	return nonce, nil
}

func (service *ProvisioningService) signString(message []byte, privateKey crypto.PrivateKey) (string, error) {
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("not an RSA private key")
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	privatekeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)
	block, _ := pem.Decode([]byte(string(privatekeyPEM)))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("failed to parse private key")
	}

	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", errors.New("failed to sign message")
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	return signatureBase64, nil
}

func (service *ProvisioningService) createSignedString(nonce []byte, fwNonce []byte, privateKey crypto.PrivateKey) (string, error) {
	arr := append(fwNonce, nonce...)
	signature, err := service.signString(arr, privateKey)
	if err != nil {
		log.Error("Error signing string:", err)
		return "", err
	}
	return signature, nil
}
