/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"fmt"
	"os"
	"regexp"
	"rpc/internal/config"
	"rpc/pkg/utils"
	"strings"
	"time"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	log "github.com/sirupsen/logrus"
)

type Handles struct {
	privateKeyHandle string
	keyPairHandle    string
	clientCertHandle string
	rootCertHandle   string
}

func (service *ProvisioningService) AddWifiSettings() (err error) {
	// start with fresh map
	service.handlesWithCerts = make(map[string]string)

	// PruneWifiConfigs is best effort
	// it will log error messages, but doesn't stop the configuration flow
	err = service.PruneWifiConfigs()
	if err != nil {
		return err
	}
	err = service.EnableWifiPort()
	if err != nil {
		return err
	}
	return service.ProcessWifiConfigs()
}

func (service *ProvisioningService) PruneWifiConfigs() (err error) {
	// get these handles BEFORE deleting the wifi profiles
	certHandles, keyPairHandles, err := service.GetWifiIeee8021xCerts()
	if err != nil {
		return err
	}
	wifiEndpointSettings, err := service.interfacedWsmanMessage.GetWiFiSettings()
	if err != nil {
		return err
	}

	for _, wifiSetting := range wifiEndpointSettings {
		// while testing, saw some cases where the PullResponse returned items with no InstanceID?
		if wifiSetting.InstanceID == "" {
			// Skip wifiSettings with no InstanceID
			continue
		}
		log.Infof("deleting wifiSetting: %s", wifiSetting.InstanceID)
		err := service.interfacedWsmanMessage.DeleteWiFiSetting(wifiSetting.InstanceID)
		if err != nil {
			log.Infof("unable to delete: %s %s", wifiSetting.InstanceID, err)
			err = utils.DeleteConfigsFailed
			continue
		}

		log.Infof("successfully deleted wifiSetting: %s", wifiSetting.InstanceID)
	}

	service.PruneCerts(certHandles, keyPairHandles)

	return err
}

func (service *ProvisioningService) GetWifiIeee8021xCerts() (certHandles, keyPairHandles []string, err error) {
	publicCerts, err := service.interfacedWsmanMessage.GetPublicKeyCerts()
	if err != nil {
		return []string{}, []string{}, err
	}
	credentialRelationships, err := service.interfacedWsmanMessage.GetCredentialRelationships()
	if err != nil {
		return []string{}, []string{}, err
	}
	certHandleMap := make(map[string]bool)
	for _, credentialContext := range credentialRelationships.CredentialContext {
		inParams := credentialContext.ElementInContext.ReferenceParameters
		providesPrams := credentialContext.ElementProvidingContext.ReferenceParameters
		if providesPrams.ResourceURI == `http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings` {
			id := inParams.GetSelectorValue("InstanceID")
			certHandleMap[id] = true
			for j := range publicCerts {
				if publicCerts[j].InstanceID == id {
					service.handlesWithCerts[id] = publicCerts[j].X509Certificate
				}
			}
		}
	}
	for k := range certHandleMap {
		if k != "" {
			certHandles = append(certHandles, k)
		}
	}
	if len(certHandles) == 0 {
		return certHandles, keyPairHandles, err
	}

	keyPairHandleMap := make(map[string]bool)
	dependencies, _ := service.interfacedWsmanMessage.GetConcreteDependencies()
	for i := range dependencies {
		antecedent := &dependencies[i].Antecedent.ReferenceParameters
		if antecedent.ResourceURI != `http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate` {
			continue
		}
		dependent := &dependencies[i].Dependent.ReferenceParameters
		if dependent.ResourceURI != `http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair` {
			continue
		}
		for _, certHandle := range certHandles {
			if !antecedent.HasSelector("InstanceID", certHandle) {
				continue
			}
			id := dependent.GetSelectorValue("InstanceID")
			keyPairHandleMap[id] = true
		}
	}
	for k := range keyPairHandleMap {
		if k != "" {
			keyPairHandles = append(keyPairHandles, k)
		}
	}

	return certHandles, keyPairHandles, err
}

func (service *ProvisioningService) ProcessWifiConfigs() error {
	lc := service.flags.LocalConfig
	var successes []string
	var failures []string
	for i, cfg := range lc.WifiConfigs {
		log.Info("configuring wifi profile: ", cfg.ProfileName)
		err := service.ProcessWifiConfig(&cfg)
		if err != nil {
			log.Error("failed configuring: ", cfg.ProfileName)
			failures = append(failures, cfg.ProfileName)
		} else {
			log.Info("successfully configured: ", cfg.ProfileName)
			successes = append(successes, cfg.ProfileName)
		}
		if i < len(lc.WifiConfigs)-1 {
			time.Sleep(3 * time.Second) // A 3-second delay is needed to fix an intermittent AMT issue if there are multiple wireless profiles
		}
	}
	if len(failures) > 0 {
		if len(successes) > 0 {
			return utils.WifiConfigurationWithWarnings
		} else {
			return utils.WiFiConfigurationFailed
		}
	}
	return nil
}

func (service *ProvisioningService) ProcessWifiConfig(wifiCfg *config.WifiConfig) (err error) {

	// profile names can only be alphanumeric (not even dashes)
	var reAlphaNum = regexp.MustCompile("[^a-zA-Z0-9]+")
	if reAlphaNum.MatchString(wifiCfg.ProfileName) {
		log.Errorf("invalid wifi profile name: %s (only alphanumeric allowed)", wifiCfg.ProfileName)
		return utils.MissingOrIncorrectWifiProfileName
	}

	// Set wifiEndpointSettings properties from wifiCfg file

	wifiEndpointSettings := wifi.WiFiEndpointSettingsRequest{
		ElementName:          wifiCfg.ProfileName,
		InstanceID:           fmt.Sprintf("Intel(r) AMT:WiFi Endpoint Settings %s", wifiCfg.ProfileName),
		SSID:                 wifiCfg.SSID,
		Priority:             wifiCfg.Priority,
		AuthenticationMethod: wifi.AuthenticationMethod(wifiCfg.AuthenticationMethod),
		EncryptionMethod:     wifi.EncryptionMethod(wifiCfg.EncryptionMethod),
	}

	// Create an empty handles reference holder
	var handles Handles
	// TODO: Check authenitcationMethod instead of profile  name
	var ieee8021xSettings models.IEEE8021xSettings
	// Find the correct Ieee8021xConfig from wifiCfg file
	if wifiCfg.Ieee8021xProfileName != "" {
		// If we find a matching Ieee8021xConfig, populate the IEEE8021xSettings and add any required private keys and certificates
		ieee8021xConfig, err := service.checkForIeee8021xConfig(wifiCfg)
		if err != nil {
			return err
		}
		if service.config.EnterpriseAssistant.EAConfigured {
			ieee8021xConfig, err = service.setIeee8021xConfigWithEA(ieee8021xConfig)
			if err != nil {
				return err
			}
		}
		ieee8021xSettings, handles, err = service.setIeee8021xConfig(ieee8021xConfig)
		if err != nil {
			return err
		}
	} else {

		// not using IEEE8021x, so set the wireless passphrase
		wifiEndpointSettings.PSKPassPhrase = wifiCfg.PskPassphrase
	}

	_, err = service.interfacedWsmanMessage.AddWiFiSettings(wifiEndpointSettings, ieee8021xSettings, "WiFi Endpoint 0", handles.clientCertHandle, handles.rootCertHandle)
	if err != nil {
		// The AddWiFiSettings call failed, return error response from go-wsman-messages
		service.RollbackAddedItems(&handles)
		return utils.WiFiConfigurationFailed //should we return err?
	}

	return nil
}

func (service *ProvisioningService) setIeee8021xConfig(ieee8021xConfig *config.Ieee8021xConfig) (ieee8021xSettings models.IEEE8021xSettings, handles Handles, err error) {
	handles = Handles{}
	handles.rootCertHandle, _ = service.GetCertHandle(ieee8021xConfig.CACert)
	if handles.rootCertHandle != "" {
		service.handlesWithCerts[handles.rootCertHandle] = ieee8021xConfig.CACert
	}
	ieee8021xSettings = models.IEEE8021xSettings{
		ElementName:            ieee8021xConfig.ProfileName,
		InstanceID:             fmt.Sprintf("Intel(r) AMT: 8021X Settings %s", ieee8021xConfig.ProfileName),
		AuthenticationProtocol: models.AuthenticationProtocol(ieee8021xConfig.AuthenticationProtocol),
		Username:               ieee8021xConfig.Username,
	}
	if ieee8021xSettings.AuthenticationProtocol == models.AuthenticationProtocol(ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2) {
		ieee8021xSettings.Password = ieee8021xConfig.Password
	}
	if ieee8021xConfig.PrivateKey != "" {
		handles.privateKeyHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.PrivateKey)
		if handles.privateKeyHandle == "" {
			handles.privateKeyHandle, err = service.interfacedWsmanMessage.AddPrivateKey(ieee8021xConfig.PrivateKey)
			if err != nil && strings.Contains(err.Error(), "already exists") {
				handles.privateKeyHandle, _ = service.GetPrivKeyHandle(ieee8021xConfig.PrivateKey)
			} else if err != nil {
				return ieee8021xSettings, handles, err
			}
			service.handlesWithCerts[handles.privateKeyHandle] = ieee8021xConfig.PrivateKey
		}
	}
	if ieee8021xConfig.ClientCert != "" {
		handles.clientCertHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.ClientCert)
		if handles.clientCertHandle == "" {
			handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(ieee8021xConfig.ClientCert)
			if err != nil && strings.Contains(err.Error(), "already exists") {
				handles.clientCertHandle, _ = service.GetCertHandle(ieee8021xConfig.ClientCert)
			} else if err != nil {
				return ieee8021xSettings, handles, err
			}
			service.handlesWithCerts[handles.clientCertHandle] = ieee8021xConfig.ClientCert
		}
	}
	if ieee8021xConfig.CACert != "" {
		handles.rootCertHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.CACert)
		if handles.rootCertHandle == "" {
			handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(ieee8021xConfig.CACert)
			service.handlesWithCerts[handles.rootCertHandle] = ieee8021xConfig.CACert
			if err != nil {
				return ieee8021xSettings, handles, err
			}
		}
	}
	return ieee8021xSettings, handles, nil
}

func (service *ProvisioningService) setIeee8021xConfigWithEA(ieee8021xConfig *config.Ieee8021xConfig) (*config.Ieee8021xConfig, error) {
	handles := Handles{}
	credentials := AuthRequest{
		Username: service.config.EnterpriseAssistant.EAUsername,
		Password: service.config.EnterpriseAssistant.EAPassword,
	}
	guid, err := service.amtCommand.GetUUID()
	if err != nil {
		return ieee8021xConfig, err
	}

	// Call GetAuthToken
	url := service.config.EnterpriseAssistant.EAAddress + "/api/authenticate/" + guid
	token, err := service.GetAuthToken(url, credentials)
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return ieee8021xConfig, utils.WiFiConfigurationFailed
	}
	devName, err := os.Hostname()
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return ieee8021xConfig, err
	}
	reqProfile := EAProfile{NodeID: guid, Domain: "", ReqID: "", AuthProtocol: ieee8021xConfig.AuthenticationProtocol, OSName: "win11", DevName: devName, Icon: 1, Ver: ""}

	//Request Profile from Microsoft EA
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/profile/" + guid
	reqResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error while requesting EA: %v", err)
		return ieee8021xConfig, err
	}

	ieee8021xConfig.PrivateKey = ""

	if ieee8021xConfig.AuthenticationProtocol == 2 {
		ieee8021xConfig.ClientCert = ""
		ieee8021xConfig.Password = reqResponse.Response.Password
		ieee8021xConfig.CACert = reqResponse.Response.RootCert
		ieee8021xConfig.Username = reqResponse.Response.Username
		return ieee8021xConfig, nil
	}

	// Generate KeyPair
	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return ieee8021xConfig, err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	// Get DERkey
	derKey, err := service.GetDERKey(handles)
	if derKey == "" || err != nil {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return ieee8021xConfig, utils.WiFiConfigurationFailed
	}

	//Request Profile from Microsoft EA
	reqProfile.DERKey = derKey
	reqProfile.KeyInstanceId = handles.keyPairHandle
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/keypair/" + guid
	KeyPairResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error generating 802.1x keypair: %v", err)
		return ieee8021xConfig, utils.WiFiConfigurationFailed
	}

	response, err := service.interfacedWsmanMessage.GeneratePKCS10RequestEx(KeyPairResponse.Response.KeyInstanceId, KeyPairResponse.Response.CSR, 1)
	if err != nil {
		return ieee8021xConfig, utils.WiFiConfigurationFailed
	}

	reqProfile.SignedCSR = response.Body.GeneratePKCS10RequestEx_OUTPUT.SignedCertificateRequest
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/csr/" + guid
	eaResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error signing the certificate: %v", err)
		return ieee8021xConfig, utils.WiFiConfigurationFailed
	}
	ieee8021xConfig.ClientCert = eaResponse.Response.Certificate
	ieee8021xConfig.CACert = eaResponse.Response.RootCert
	ieee8021xConfig.Username = eaResponse.Response.Username
	return ieee8021xConfig, nil
}

func (service *ProvisioningService) checkForIeee8021xConfig(wifiCfg *config.WifiConfig) (ieee8021xConfig *config.Ieee8021xConfig, err error) {
	for _, curCfg := range service.flags.LocalConfig.Ieee8021xConfigs {
		if curCfg.ProfileName == wifiCfg.Ieee8021xProfileName {
			ieee8021xConfig = &curCfg
			return ieee8021xConfig, nil
		}
	}
	log.Error("no matching 802.1x configuration found")
	return nil, utils.Ieee8021xConfigurationFailed
}

func (service *ProvisioningService) RollbackAddedItems(handles *Handles) {
	if handles.privateKeyHandle != "" {
		log.Infof("rolling back private key %s", handles.privateKeyHandle)
		err := service.interfacedWsmanMessage.DeletePublicPrivateKeyPair(handles.privateKeyHandle)
		if err != nil {
			log.Errorf("failed deleting private key: %s", handles.privateKeyHandle)
		} else {
			log.Debugf("successfully deleted private key: %s", handles.privateKeyHandle)
		}
	}
	if handles.keyPairHandle != "" {
		log.Infof("rolling back private key %s", handles.keyPairHandle)
		err := service.interfacedWsmanMessage.DeleteKeyPair(handles.keyPairHandle)
		if err != nil {
			log.Errorf("failed deleting keyPairHandle: %s", handles.keyPairHandle)
		} else {
			log.Debugf("successfully deleted keyPairHandle: %s", handles.keyPairHandle)
		}
	}
	if handles.clientCertHandle != "" {
		log.Infof("rolling back client cert %s", handles.clientCertHandle)
		err := service.interfacedWsmanMessage.DeletePublicCert(handles.clientCertHandle)
		if err != nil {
			log.Errorf("failed deleting client cert: %s", handles.clientCertHandle)
		} else {
			log.Debugf("successfully deleted client cert: %s", handles.clientCertHandle)
		}
	}
	if handles.rootCertHandle != "" {
		log.Infof("rolling back root cert %s", handles.rootCertHandle)
		err := service.interfacedWsmanMessage.DeletePublicCert(handles.rootCertHandle)
		if err != nil {
			log.Errorf("failed deleting root cert: %s", handles.rootCertHandle)
		} else {
			log.Debugf("successfully deleted root cert: %s", handles.rootCertHandle)
		}
	}
}
