package local

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"rpc/pkg/utils"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/general"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/ips/hostbasedsetup"
	log "github.com/sirupsen/logrus"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func (service *ProvisioningService) Activate() utils.ReturnCode {

	controlMode, err := service.amtCommand.GetControlMode()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
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
	service.setupWsmanClient(lsa.Username, lsa.Password)

	rc := utils.Success

	if service.flags.UseACM {
		rc = service.ActivateACM()
	} else if service.flags.UseCCM {
		rc = service.ActivateCCM()
	}

	return rc
}

func (service *ProvisioningService) ActivateACM() utils.ReturnCode {
	checkErrorAndLog := func(err error) bool {
		if err != nil {
			log.Error(err)
			return true
		}
		return false
	}
	// Extract the provisioning certificate
	certObject, fingerPrint, err := service.GetProvisioningCertObj()
	if checkErrorAndLog(err) {
		return utils.ActivationFailed
	}
	// Check provisioning certificate is accepted by AMT
	if checkErrorAndLog(service.CompareCertHashes(fingerPrint)) {
		return utils.ActivationFailed
	}

	generalSettings, err := service.GetGeneralSettings()
	if checkErrorAndLog(err) {
		return utils.ActivationFailed
	}

	getHostBasedSetupResponse, err := service.GetHostBasedSetupService()
	if checkErrorAndLog(err) {
		return utils.ActivationFailed
	}
	decodedNonce := getHostBasedSetupResponse.Body.IPS_HostBasedSetupService.ConfigurationNonce
	fwNonce, err := base64.StdEncoding.DecodeString(decodedNonce)
	if checkErrorAndLog(err) {
		log.Error("Error decoding fwNonce:", err)
		return utils.ActivationFailed
	}

	if checkErrorAndLog(service.injectCertificate(certObject.certChain)) {
		return utils.ActivationFailed
	}

	nonce, err := service.generateNonce()
	if checkErrorAndLog(err) {
		return utils.ActivationFailed
	}

	signedSignature, err := service.createSignedString(nonce, fwNonce, certObject.privateKey)
	if checkErrorAndLog(err) {
		return utils.ActivationFailed
	}

	_, err = service.sendAdminSetup(generalSettings.Body.AMTGeneralSettings.DigestRealm, nonce, signedSignature)
	if checkErrorAndLog(err) {
		return utils.ActivationFailed
	}
	return utils.Success
}

func (service *ProvisioningService) ActivateCCM() utils.ReturnCode {
	generalSettings, err := service.GetGeneralSettings()
	if err != nil {
		log.Error(err)
		return utils.ActivationFailed
	}
	_, err = service.HostBasedSetup(generalSettings.Body.AMTGeneralSettings.DigestRealm, service.config.Password)
	if err != nil {
		log.Error(err)
		return utils.ActivationFailed
	}
	log.Info("Status: Device activated in Client Control Mode")
	return utils.Success
}

func (service *ProvisioningService) GetGeneralSettings() (general.Response, error) {
	message := service.amtMessages.GeneralSettings.Get()
	response, err := service.client.Post(message)
	if err != nil {
		return general.Response{}, err
	}
	var generalSettings general.Response
	err = xml.Unmarshal([]byte(response), &generalSettings)
	if err != nil {
		return general.Response{}, err
	}
	return generalSettings, nil
}

func (service *ProvisioningService) HostBasedSetup(digestRealm string, password string) (utils.ReturnCode, error) {
	message := service.ipsMessages.HostBasedSetupService.Setup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password)
	response, err := service.client.Post(message)
	if err != nil {
		return utils.AMTConnectionFailed, err
	}
	var hostBasedSetupResponse hostbasedsetup.Response
	err = xml.Unmarshal([]byte(response), &hostBasedSetupResponse)
	if err != nil {
		return utils.ActivationFailed, err
	}
	if hostBasedSetupResponse.Body.Setup_OUTPUT.ReturnValue != 0 {
		return utils.ActivationFailed, errors.New("unable to activate CCM, check to make sure the device is not alreacy activated")
	}
	return utils.Success, nil
}

func (service *ProvisioningService) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	message := service.ipsMessages.HostBasedSetupService.Get()
	response, err := service.client.Post(message)
	if err != nil {
		return hostbasedsetup.Response{}, err
	}
	var getHostBasedSetupResponse hostbasedsetup.Response
	err = xml.Unmarshal([]byte(response), &getHostBasedSetupResponse)
	if err != nil {
		return hostbasedsetup.Response{}, err
	}
	return getHostBasedSetupResponse, nil
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

func dumpPfx(pfxobj CertsAndKeys) (ProvisioningCertObj, string, error) {
	if len(pfxobj.certs) == 0 {
		return ProvisioningCertObj{}, "", errors.New("no certificates found")
	}
	if len(pfxobj.keys) == 0 {
		return ProvisioningCertObj{}, "", errors.New("no private keys found")
	}
	var provisioningCertificateObj ProvisioningCertObj
	var interObj []CertificateObject
	var leaf CertificateObject
	var root CertificateObject
	var fingerprint string

	for i, cert := range pfxobj.certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pem := cleanPEM(string(pem.EncodeToMemory(pemBlock)))
		certificateObject := CertificateObject{pem: pem, subject: cert.Subject.String(), issuer: cert.Issuer.String()}

		if i == 0 {
			leaf = certificateObject
		} else if cert.Subject.String() == cert.Issuer.String() {
			root = certificateObject
			der := cert.Raw
			hash := sha256.Sum256(der)
			fingerprint = hex.EncodeToString(hash[:])
		} else {
			interObj = append(interObj, certificateObject)
		}
	}
	provisioningCertificateObj.certChain = append(provisioningCertificateObj.certChain, leaf.pem)
	for _, inter := range interObj {
		provisioningCertificateObj.certChain = append(provisioningCertificateObj.certChain, inter.pem)
	}
	provisioningCertificateObj.certChain = append(provisioningCertificateObj.certChain, root.pem)
	provisioningCertificateObj.privateKey = pfxobj.keys[0]

	return provisioningCertificateObj, fingerprint, nil
}

func convertPfxToObject(pfxb64 string, passphrase string) (CertsAndKeys, error) {
	pfx, err := base64.StdEncoding.DecodeString(pfxb64)
	if err != nil {
		return CertsAndKeys{}, err
	}
	privateKey, certificate, extraCerts, err := pkcs12.DecodeChain(pfx, passphrase)
	if err != nil {
		return CertsAndKeys{}, errors.New("Decrypting provisioning certificate failed")
	}
	certs := append([]*x509.Certificate{certificate}, extraCerts...)
	pfxOut := CertsAndKeys{certs: certs, keys: []interface{}{privateKey}}

	return pfxOut, nil
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
	return errors.New("The root of the provisioning certificate does not match any of the trusted roots in AMT.")
}

func (service *ProvisioningService) injectCertificate(certChain []string) error {
	firstIndex := 0
	lastIndex := len(certChain) - 1
	for i, cert := range certChain {
		isLeaf := i == firstIndex
		isRoot := i == lastIndex

		err := service.AddNextCertInChain(cert, isLeaf, isRoot)
		if err != nil {
			log.Error(err)
			return errors.New("Failed to add certificate to AMT.")
		}
	}
	return nil
}

func (service *ProvisioningService) AddNextCertInChain(cert string, isLeaf bool, isRoot bool) error {
	message := service.ipsMessages.HostBasedSetupService.AddNextCertInChain(cert, isLeaf, isRoot)
	response, err := service.client.Post(message)
	if err != nil {
		return err
	}
	var addCertResponse hostbasedsetup.Response
	err = xml.Unmarshal([]byte(response), &addCertResponse)
	if err != nil {
		return err
	}
	if addCertResponse.Body.AdminSetup_OUTPUT.ReturnValue != 0 {
		return errors.New("unable to activate ACM")
	}
	return nil
}

func (service *ProvisioningService) generateNonce() ([]byte, error) {
	nonce := make([]byte, 20)
	_, err := rand.Read(nonce)
	if err != nil {
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

func (service *ProvisioningService) sendAdminSetup(digestRealm string, nonce []byte, signature string) (utils.ReturnCode, error) {
	password := service.config.ACMSettings.AMTPassword
	message := service.ipsMessages.HostBasedSetupService.AdminSetup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password, base64.StdEncoding.EncodeToString(nonce), hostbasedsetup.SigningAlgorithmRSASHA2256, signature)
	response, err := service.client.Post(message)
	if err != nil && err.Error() != "Post \"http://localhost:16992/wsman\": EOF" {
		log.Error(err)
		return utils.ActivationFailed, err
	}
	if response != nil {
		var hostBasedSetupResponse hostbasedsetup.Response
		err = xml.Unmarshal([]byte(response), &hostBasedSetupResponse)
		if err != nil {
			log.Error(err)
			return utils.ActivationFailed, err
		}
		if hostBasedSetupResponse.Body.AdminSetup_OUTPUT.ReturnValue != 0 {
			log.Error("hostBasedSetupResponse.Body.AdminSetup_OUTPUT.ReturnValue: ", hostBasedSetupResponse.Body.AdminSetup_OUTPUT.ReturnValue)
			return utils.ActivationFailed, errors.New("unable to activate in ACM")
		}
	} else {
		controlMode, err := service.amtCommand.GetControlMode()
		if err != nil {
			log.Error(err)
			return utils.AMTConnectionFailed, err
		}
		if controlMode != 2 {
			log.Error("unable to activate in ACM. control mode: ", controlMode)
			return utils.UnableToActivate, err
		}
	}
	log.Info("Status: Device activated in Admin Control Mode")
	return utils.Success, nil
}
