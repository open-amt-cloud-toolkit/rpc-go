package local

import (
	"fmt"
	"regexp"
	"rpc/internal/config"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Configure() (err error) {
	service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password)
	switch service.flags.SubCommand {
	case utils.SubCommandAddWifiSettings:
		return service.AddWifiSettings()
	case utils.SubCommandEnableWifiPort:
		return service.EnableWifiPort()
	case utils.SubCommandSetMEBx:
		return service.SetMebx()
	default:
	}
	return utils.IncorrectCommandLineParameters
}

func (service *ProvisioningService) SetMebx() (err error) {
	response, err := service.interfacedWsmanMessage.SetupMEBX(service.flags.MEBxPassword)
	log.Info(response)
	if err != nil {
		log.Error("Failed to configure MEBx Password.")
	} else {
		log.Info("Successfully configured MEBx Password.")
	}
	return err
}

func (service *ProvisioningService) EnableWifiPort() (err error) {
	err = service.EnableWifi()
	if err != nil {
		log.Error("Failed to enable wifi port and local profile synchronization.")
	} else {
		log.Info("Successfully enabled wifi port and local profile synchronization.")
	}
	return err
}

func (service *ProvisioningService) AddWifiSettings() (err error) {
	// start with fresh map
	service.handlesWithCerts = make(map[string]string)

	// PruneWifiConfigs is best effort
	// it will log error messages, but doesn't stop the configuration flow
	service.PruneWifiConfigs()
	err = service.EnableWifi()
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

	var successes []string
	var failures []string
	for _, wifiSetting := range wifiEndpointSettings {
		// while testing, saw some cases where the PullResponse returned items with no InstanceID?
		if wifiSetting.InstanceID == "" {
			continue
		}
		log.Infof("deleting wifiSetting: %s", wifiSetting.InstanceID)
		err := service.interfacedWsmanMessage.DeleteWiFiSetting(wifiSetting.InstanceID)
		if err != nil {
			log.Infof("unable to delete: %s %s", wifiSetting.InstanceID, err)
			failures = append(failures, wifiSetting.InstanceID)
			continue
		}
		// logged success, no need to keep the successes
		_ = append(successes, wifiSetting.InstanceID)
	}

	service.PruneWifiIeee8021xCerts(certHandles, keyPairHandles)

	if len(failures) > 0 {
		return utils.DeleteWifiConfigFailed // logged failures already....
	}
	return nil
}

func (service *ProvisioningService) PruneWifiIeee8021xCerts(certHandles []string, keyPairHandles []string) (failedCertHandles []string, failedKeyPairHandles []string) {
	for _, handle := range certHandles {
		err := service.interfacedWsmanMessage.DeletePublicCert(handle)
		if err != nil {
			failedCertHandles = append(failedCertHandles, handle)
		} else {
			delete(service.handlesWithCerts, handle)
		}
	}
	for _, handle := range keyPairHandles {
		err := service.interfacedWsmanMessage.DeletePublicPrivateKeyPair(handle)
		if err != nil {
			failedKeyPairHandles = append(failedKeyPairHandles, handle)
		} else {
			delete(service.handlesWithCerts, handle)
		}
	}
	return failedCertHandles, failedKeyPairHandles
}

func (service *ProvisioningService) GetWifiIeee8021xCerts() (certHandles, keyPairHandles []string, err error) {
	publicCerts, err := service.interfacedWsmanMessage.GetPublicKeyCerts()
	if err != nil {
		return certHandles, keyPairHandles, err
	}
	_, err = service.interfacedWsmanMessage.GetPublicPrivateKeyPairs()
	if err != nil {
		return certHandles, keyPairHandles, err
	}
	credentials, err := service.interfacedWsmanMessage.GetCredentialRelationships()
	if err != nil {
		return certHandles, keyPairHandles, err
	}
	certHandleMap := make(map[string]bool)
	for i := range credentials {
		inParams := &credentials[i].ElementInContext.ReferenceParameters
		providesPrams := &credentials[i].ElementProvidingContext.ReferenceParameters
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
	for _, cfg := range lc.WifiConfigs {
		log.Info("configuring wifi profile: ", cfg.ProfileName)
		err := service.ProcessWifiConfig(&cfg)
		if err != nil {
			log.Error("failed configuring: ", cfg.ProfileName)
			failures = append(failures, cfg.ProfileName)
		} else {
			log.Info("successfully configured: ", cfg.ProfileName)
			successes = append(successes, cfg.ProfileName)
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

	// Find the correct Ieee8021xConfig from wifiCfg file
	var ieee8021xConfig config.Ieee8021xConfig
	var found bool
	for _, curCfg := range service.flags.LocalConfig.Ieee8021xConfigs {
		if curCfg.ProfileName == wifiCfg.ProfileName {
			ieee8021xConfig = curCfg
			found = true
			break
		}
	}

	// Create an empty handles reference holder
	handles := Handles{}

	// If we find a matching Ieee8021xConfig, populate the IEEE8021xSettings and add any required private keys and certificates
	var ieee8021xSettings models.IEEE8021xSettings
	if found {
		ieee8021xSettings = models.IEEE8021xSettings{
			ElementName:            ieee8021xConfig.ProfileName,
			InstanceID:             fmt.Sprintf("Intel(r) AMT: 8021X Settings %s", ieee8021xConfig.ProfileName),
			AuthenticationProtocol: models.AuthenticationProtocol(ieee8021xConfig.AuthenticationProtocol),
			Username:               ieee8021xConfig.Username,
		}
		if ieee8021xSettings.AuthenticationProtocol == models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 {
			ieee8021xSettings.Password = ieee8021xConfig.Password
		}
		if ieee8021xConfig.PrivateKey != "" {
			handles.privateKeyHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.ClientCert)
			if handles.privateKeyHandle == "" {
				handles.privateKeyHandle, err = service.interfacedWsmanMessage.AddPrivateKey(ieee8021xConfig.PrivateKey)
				service.handlesWithCerts[handles.privateKeyHandle] = ieee8021xConfig.PrivateKey
				if err != nil {
					return err
				}
			}
		}
		if ieee8021xConfig.ClientCert != "" {
			handles.clientCertHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.ClientCert)
			if handles.clientCertHandle == "" {
				handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(ieee8021xConfig.ClientCert)
				service.handlesWithCerts[handles.clientCertHandle] = ieee8021xConfig.ClientCert
				if err != nil {
					return err
				}
			}
		}
		if ieee8021xConfig.CACert != "" {
			handles.rootCertHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.CACert)
			if handles.rootCertHandle == "" {
				handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(ieee8021xConfig.CACert)
				service.handlesWithCerts[handles.rootCertHandle] = ieee8021xConfig.CACert
				if err != nil {
					return err
				}
			}
		}
	} else {
		// not using IEEE8021x, so set the wireless passphrase
		wifiEndpointSettings.PSKPassPhrase = wifiCfg.PskPassphrase
	}
	// // QUESTION: why check for these?  why not just check if a Ieee8021xProfileName is present?  or maybe profile name and authmethod?
	// if wifiEndpointSettings.AuthenticationMethod == wifi.AuthenticationMethod_WPA_IEEE8021x ||
	// 	wifiEndpointSettings.AuthenticationMethod == wifi.AuthenticationMethod_WPA2_IEEE8021x {
	// 	ieee8021xSettings, err := service.ProcessIeee8012xConfig(wifiCfg.Ieee8021xProfileName, &handles)
	// 	if err != nil {
	// 		service.RollbackAddedItems(&handles)
	// 		return err
	// 	}
	// } else {
	// 	wifiEndpointSettings.PSKPassPhrase = wifiCfg.PskPassphrase
	// }
	response, err := service.wsmanMessages.AMT.WiFiPortConfigurationService.AddWiFiSettings(
		wifiEndpointSettings,
		ieee8021xSettings,
		"WiFi Endpoint 0",
		handles.clientCertHandle,
		handles.rootCertHandle)
	if err != nil {
		// The AddWiFiSettings call failed, return error response from go-wsman-messages
		service.RollbackAddedItems(&handles)
		return utils.WSMANMessageError
	}
	if response.Body.AddWiFiSettings_OUTPUT.ReturnValue != 0 {
		// AMT returned an unsuccessful response
		service.RollbackAddedItems(&handles)
		log.Errorf("AddWiFiSettings_OUTPUT.ReturnValue: %d", response.Body.AddWiFiSettings_OUTPUT.ReturnValue)
		return utils.WiFiConfigurationFailed
	}
	return nil
}

// func (service *ProvisioningService) ProcessIeee8012xConfig(profileName string, handles *Handles) (ieee8021xSettings ieee8021x.IEEE8021xSettingsRequest, err error) {
// 	ieee8021xSettings = ieee8021x.IEEE8021xSettingsRequest{}
// 	// find the matching configuration
// 	var ieee8021xConfig config.Ieee8021xConfig
// 	var found bool
// 	for _, curCfg := range service.flags.LocalConfig.Ieee8021xConfigs {
// 		if curCfg.ProfileName == profileName {
// 			ieee8021xConfig = curCfg
// 			found = true
// 			break
// 		}
// 	}
// 	if !found {
// 		log.Errorf("missing Ieee8021xConfig %s", profileName)
// 		return ieee8021xSettings, utils.MissingIeee8021xConfiguration
// 	}

// 	// translate from configuration to settings
// 	ieee8021xSettings.ElementName = ieee8021xConfig.ProfileName
// 	ieee8021xSettings.InstanceID = fmt.Sprintf("Intel(r) AMT: 8021X Settings %s", ieee8021xConfig.ProfileName)
// 	ieee8021xSettings.AuthenticationProtocol = ieee8021x.AuthenticationProtocol(ieee8021xConfig.AuthenticationProtocol)
// 	ieee8021xSettings.Username = ieee8021xConfig.Username
// 	if ieee8021xSettings.AuthenticationProtocol == ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 {
// 		ieee8021xSettings.Password = ieee8021xConfig.Password
// 	}

// 	// add key and certs
// 	if ieee8021xConfig.PrivateKey != "" {
// 		handles.privateKeyHandle, err = service.AddPrivateKey(ieee8021xConfig.PrivateKey)
// 		if err != nil {
// 			return ieee8021xSettings, err
// 		}
// 	}
// 	if ieee8021xConfig.ClientCert != "" {
// 		handles.clientCertHandle, err = service.AddClientCert(ieee8021xConfig.ClientCert)
// 		if err != nil {
// 			return ieee8021xSettings, err
// 		}
// 	}
// 	handles.rootCertHandle, err = service.AddTrustedRootCert(ieee8021xConfig.CACert)
// 	return ieee8021xSettings, err
// }

func (service *ProvisioningService) EnableWifi() (err error) {
	err = service.interfacedWsmanMessage.EnableWiFi()
	if err != nil {
		return err
	}
	return nil
}

type Handles struct {
	privateKeyHandle string
	clientCertHandle string
	rootCertHandle   string
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
