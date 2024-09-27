/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func (service *ProvisioningService) Activate() error {

	controlMode, err := service.amtCommand.GetControlMode()
	if err != nil {
		return utils.ActivationFailedGetControlMode
	}
	if controlMode != 0 {
		log.Error("Device is already activated")
		return utils.UnableToActivate
	}

	service.CheckAndEnableAMT(service.flags.SkipIPRenew)

	// for local activation, wsman client needs local system account credentials
	lsa, err := service.amtCommand.GetLocalSystemAccount()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}

	// Get AMT version to determine what activation flow to use
	versionStr, err := service.amtCommand.GetVersionDataFromME("AMT", service.flags.AMTTimeoutDuration)
	if err != nil {
		log.Error(err)
		return err
	}

	// Split the version string into major, minor, patch components
	versionParts := strings.Split(versionStr, ".")
	if len(versionParts) != 3 {
		log.Error("Invalid version format")
		return utils.GenericFailure
	}

	// Parse the major, minor, and patch versions
	major, err := strconv.Atoi(versionParts[0])
	if err != nil {
		log.Error("Error parsing major version:", err)
		return err
	}

	// If AMT Major version is greater than 15, use TLS for activation
	useTLS := major > 15
	tlsConfig := &tls.Config{}
	if useTLS {
		config := service.config.ACMSettings
		certsAndKeys, err := convertPfxToObject(config.ProvisioningCert, config.ProvisioningCertPwd)
		if err != nil {
			return err
		}

		for i := range certsAndKeys.certs {
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certsAndKeys.certs[i].Raw,
			})

			keyPEMBlock, err := marshalPrivateKeyToPEM(certsAndKeys.keys[i])
			if err != nil {
				return err
			}

			tlsCert := tls.Certificate{
				Certificate: [][]byte{certPEM},
				PrivateKey:  keyPEMBlock[i],
				Leaf:        certsAndKeys.certs[i],
			}

			tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
		}

		// Use the AMT Certificate response to verify AMT device
		_, err = service.StartSecureHostBasedConfiguration()
		if err != nil {
			return err
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	service.interfacedWsmanMessage.SetupWsmanClient(lsa.Username, lsa.Password, useTLS, log.GetLevel() == log.TraceLevel, tlsConfig)

	if service.flags.UseACM && major > 15 {
		err = service.ActivateSecureACM()
		if err == nil {
			log.Info("Status: Device activated in Admin Control Mode")
		}
	} else if service.flags.UseACM && major < 16 {
		err = service.ActivateACM()
		if err == nil {
			log.Info("Status: Device activated in Admin Control Mode")
		}
	} else if service.flags.UseCCM {
		err = service.ActivateCCM()
	}

	return err
}

func checkCertAlgoSupported(certAlgorithm x509.SignatureAlgorithm) (value uint8, err error) {
	switch certAlgorithm {
	case x509.MD5WithRSA:
		value = 0
		err = nil
		break
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		value = 1
		err = nil
		break
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		value = 2
		err = nil
		break
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		value = 3
		err = nil
		break
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		value = 5
		err = nil
		break
	default:
		value = 99
		err = errors.New("Unsupported certificate algorithm")
	}

	return value, err
}

func (service *ProvisioningService) StartSecureHostBasedConfiguration() (amt.SecureHBasedResponse, error) {
	// Get the provisioning certificate
	certObject, _, err := service.GetProvisioningCertObj()
	if err != nil {
		return amt.SecureHBasedResponse{}, err
	}

	// Check fingerPrint length
	if len(certObject.certChain[0]) > 64 {
		return amt.SecureHBasedResponse{}, utils.ActivationFailedCertHash
	}

	var certHashByteArray [64]byte
	copy(certHashByteArray[:], certObject.certChain[0])

	certAlgo, err := checkCertAlgoSupported(certObject.certificateAlgorithm)
	if err != nil {
		return amt.SecureHBasedResponse{}, utils.ActivationFailedCertHash
	}
	// Call StartConfigurationHBased
	params := amt.SecureHBasedParameters{
		CertHash:      certHashByteArray,
		CertAlgorithm: certAlgo,
	}

	response, err := service.amtCommand.StartConfigurationHBased(params)
	if err != nil {
		return amt.SecureHBasedResponse{}, err
	}

	log.Trace("Certificate Hash from AMT: %s", response.AMTCertHash)

	return response, nil
}

func (service *ProvisioningService) ActivateSecureACM() error {
	getSetupAndConfigurationService, err := service.interfacedWsmanMessage.GetSetupAndConfigurationService()
	if err != nil {
		return utils.ActivationFailedSetupService
	}

	log.Trace("GetSetupAndConfigurationService response: %v", getSetupAndConfigurationService)

	return nil
}

func (service *ProvisioningService) ActivateACM() error {

	// Extract the provisioning certificate
	certObject, fingerPrint, err := service.GetProvisioningCertObj()
	if err != nil {
		return err
	}
	// Check provisioning certificate is accepted by AMT
	err = service.CompareCertHashes(fingerPrint)
	if err != nil {
		return err
	}

	generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
	if err != nil {
		return utils.ActivationFailedGeneralSettings
	}

	getHostBasedSetupResponse, err := service.interfacedWsmanMessage.GetHostBasedSetupService()
	if err != nil {
		return utils.ActivationFailedSetupService
	}
	decodedNonce := getHostBasedSetupResponse.Body.GetResponse.ConfigurationNonce
	fwNonce, err := base64.StdEncoding.DecodeString(decodedNonce)
	if err != nil {
		return utils.ActivationFailedDecode64
	}

	err = service.injectCertificate(certObject.certChain)
	if err != nil {
		return err
	}

	nonce, err := service.generateNonce()
	if err != nil {
		return err
	}

	signedSignature, err := service.createSignedString(nonce, fwNonce, certObject.privateKey)
	if err != nil {
		return err
	}

	_, err = service.interfacedWsmanMessage.HostBasedSetupServiceAdmin(service.config.ACMSettings.AMTPassword, generalSettings.Body.GetResponse.DigestRealm, nonce, signedSignature)
	if err != nil {
		controlMode, err := service.amtCommand.GetControlMode()
		if err != nil {
			return utils.ActivationFailedGetControlMode
		}
		if controlMode != 2 {
			return utils.ActivationFailedControlMode
		}
		return nil
	}
	return nil
}

func (service *ProvisioningService) ActivateCCM() error {
	generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
	if err != nil {
		return utils.ActivationFailedGeneralSettings
	}
	_, err = service.interfacedWsmanMessage.HostBasedSetupService(generalSettings.Body.GetResponse.DigestRealm, service.config.Password)
	if err != nil {
		return utils.ActivationFailedSetupService
	}
	log.Info("Status: Device activated in Client Control Mode")
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
	certChain            []string
	privateKey           crypto.PrivateKey
	certificateAlgorithm x509.SignatureAlgorithm
}

func marshalPrivateKeyToPEM(key interface{}) ([]byte, error) {
	switch keyType := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(keyType),
		}), nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(keyType)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}), nil
	case ed25519.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyType.Seed(),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
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
		return CertsAndKeys{}, utils.ActivationFailedDecode64
	}
	privateKey, certificate, extraCerts, err := pkcs12.DecodeChain(pfx, passphrase)
	if err != nil {
		if strings.Contains(err.Error(), "decryption password incorrect") {
			return CertsAndKeys{}, utils.ActivationFailedWrongCertPass
		}

		return CertsAndKeys{}, utils.ActivationFailedInvalidProvCert
	}
	certs := append([]*x509.Certificate{certificate}, extraCerts...)
	pfxOut := CertsAndKeys{certs: certs, keys: []interface{}{privateKey}}

	return pfxOut, nil
}

func dumpPfx(pfxobj CertsAndKeys) (ProvisioningCertObj, string, error) {
	if len(pfxobj.certs) == 0 {
		return ProvisioningCertObj{}, "", utils.ActivationFailedNoCertFound
	}
	if len(pfxobj.keys) == 0 {
		return ProvisioningCertObj{}, "", utils.ActivationFailedNoPrivKeys
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

	if fingerprint == "" {
		return provisioningCertificateObj, "", utils.ActivationFailedNoRootCertFound
	}

	// Order the certificates from leaf to root
	orderedCertificateList := orderCertificates(certificateList)

	// Add them to the certChain in order
	for _, cert := range orderedCertificateList {
		provisioningCertificateObj.certChain = append(provisioningCertificateObj.certChain, cert.pem)
	}

	// Add the private key
	provisioningCertificateObj.privateKey = pfxobj.keys[0]

	// Add the certificate algorithm
	provisioningCertificateObj.certificateAlgorithm = pfxobj.certs[0].SignatureAlgorithm

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
		return utils.ActivationFailedGetCertHash
	}
	for _, v := range result {
		if v.Hash == fingerPrint {
			return nil
		}
	}
	return utils.ActivationFailedProvCertNoMatch
}

func (service *ProvisioningService) injectCertificate(certChain []string) error {
	firstIndex := 0
	lastIndex := len(certChain) - 1
	for i, cert := range certChain {
		isLeaf := i == firstIndex
		isRoot := i == lastIndex

		_, err := service.interfacedWsmanMessage.AddNextCertInChain(cert, isLeaf, isRoot)
		if err != nil {
			return utils.ActivationFailedAddCert
		}
	}
	return nil
}

func (service *ProvisioningService) generateNonce() ([]byte, error) {
	nonce := make([]byte, 20)
	// fills nonce with 20 random bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, utils.ActivationFailedGenerateNonce
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
		return "", utils.ActivationFailedSignString
	}
	return signature, nil
}
