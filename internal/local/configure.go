package local

import (
	"fmt"
	"regexp"
	"rpc/internal/config"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Configure() utils.ReturnCode {
	service.setupWsmanClient("admin", service.flags.Password)
	switch service.flags.SubCommand {
	case utils.SubCommandAddWifiSettings:
		return service.AddWifiSettings()
	case utils.SubCommandEnableWifiPort:
		return service.EnableWifiPort()
	default:
	}
	return utils.IncorrectCommandLineParameters
}

func (service *ProvisioningService) EnableWifiPort() utils.ReturnCode {
	rc := service.EnableWifi()
	if rc != utils.Success {
		log.Error("Failed to enable wifi port and local profile synchronization.")
	} else {
		log.Info("Successfully enabled wifi port and local profile synchronization.")
	}
	return rc
}

func (service *ProvisioningService) AddWifiSettings() utils.ReturnCode {
	// start with fresh map
	service.handlesWithCerts = make(map[string]string)

	// PruneWifiConfigs is best effort
	// it will log error messages, but doesn't stop the configuration flow
	service.PruneWifiConfigs()
	rc := service.EnableWifi()
	if rc != utils.Success {
		return rc
	}
	return service.ProcessWifiConfigs()
}

func (service *ProvisioningService) PruneWifiConfigs() utils.ReturnCode {
	// get these handles BEFORE deleting the wifi profiles
	certHandles, keyPairHandles := service.GetWifiIeee8021xCerts()

	var pullRspEnv wifi.PullResponseEnvelope
	rc := service.EnumPullUnmarshal(
		service.cimMessages.WiFiEndpointSettings.Enumerate,
		service.cimMessages.WiFiEndpointSettings.Pull,
		&pullRspEnv,
	)
	if rc != utils.Success {
		return rc
	}
	var successes []string
	var failures []string
	for _, wifiSetting := range pullRspEnv.Body.PullResponse.Items {
		// while testing, saw some cases where the PullResponse returned items with no InstanceID?
		if wifiSetting.InstanceID == "" {
			continue
		}
		log.Infof("deleting wifiSetting: %s", wifiSetting.InstanceID)
		xmlMsg := service.cimMessages.WiFiEndpointSettings.Delete(wifiSetting.InstanceID)
		// the response does not return any additional useful information
		_, err := service.client.Post(xmlMsg)
		if err != nil {
			log.Infof("unable to delete: %s %s", wifiSetting.InstanceID, err)
			failures = append(failures, wifiSetting.InstanceID)
			continue
		}
		successes = append(successes, wifiSetting.InstanceID)
	}

	service.PruneWifiIeee8021xCerts(certHandles, keyPairHandles)

	if len(failures) > 0 {
		return utils.DeleteWifiConfigFailed
	}
	return utils.Success
}

func (service *ProvisioningService) PruneWifiIeee8021xCerts(certHandles []string, keyPairHandles []string) (failedCertHandles []string, failedKeyPairHandles []string) {
	for _, handle := range certHandles {
		rc := service.DeletePublicCert(handle)
		if rc != utils.Success {
			failedCertHandles = append(failedCertHandles, handle)
		} else {
			delete(service.handlesWithCerts, handle)
		}
	}
	for _, handle := range keyPairHandles {
		rc := service.DeletePublicPrivateKeyPair(handle)
		if rc != utils.Success {
			failedKeyPairHandles = append(failedKeyPairHandles, handle)
		} else {
			delete(service.handlesWithCerts, handle)
		}
	}
	return failedCertHandles, failedKeyPairHandles
}

func (service *ProvisioningService) GetWifiIeee8021xCerts() (certHandles []string, keyPairHandles []string) {

	var publicCerts []publickey.PublicKeyCertificate
	service.GetPublicKeyCerts(&publicCerts)
	var keyPairs []publicprivate.PublicPrivateKeyPair
	service.GetPublicPrivateKeyPairs(&keyPairs)
	credentials, rc := service.GetCredentialRelationships()
	if rc != utils.Success {
		return certHandles, keyPairHandles
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
		return certHandles, keyPairHandles
	}

	keyPairHandleMap := make(map[string]bool)
	dependencies, _ := service.GetConcreteDependencies()
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

	return certHandles, keyPairHandles
}

func (service *ProvisioningService) ProcessWifiConfigs() utils.ReturnCode {
	lc := service.flags.LocalConfig
	var successes []string
	var failures []string
	for _, cfg := range lc.WifiConfigs {
		log.Info("configuring wifi profile: ", cfg.ProfileName)
		rc := service.ProcessWifiConfig(&cfg)
		if rc != utils.Success {
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
	return utils.Success
}

func (service *ProvisioningService) ProcessWifiConfig(wifiCfg *config.WifiConfig) utils.ReturnCode {

	// profile names can only be alphanumeric (not even dashes)
	var reAlphaNum = regexp.MustCompile("[^a-zA-Z0-9]+")
	if reAlphaNum.MatchString(wifiCfg.ProfileName) {
		log.Errorf("invalid wifi profile name: %s (only alphanumeric allowed)", wifiCfg.ProfileName)
		return utils.MissingOrIncorrectWifiProfileName
	}

	wiFiEndpointSettings := models.WiFiEndpointSettings{
		ElementName:          wifiCfg.ProfileName,
		InstanceID:           fmt.Sprintf("Intel(r) AMT:WiFi Endpoint Settings %s", wifiCfg.ProfileName),
		SSID:                 wifiCfg.SSID,
		Priority:             wifiCfg.Priority,
		AuthenticationMethod: models.AuthenticationMethod(wifiCfg.AuthenticationMethod),
		EncryptionMethod:     models.EncryptionMethod(wifiCfg.EncryptionMethod),
	}
	var ieee8021xSettings *models.IEEE8021xSettings
	handles := Handles{}

	if wiFiEndpointSettings.AuthenticationMethod == models.AuthenticationMethod_WPA_IEEE8021x ||
		wiFiEndpointSettings.AuthenticationMethod == models.AuthenticationMethod_WPA2_IEEE8021x {

		ieee8021xSettings = &models.IEEE8021xSettings{}
		rc := service.ProcessIeee8012xConfig(wifiCfg.Ieee8021xProfileName, ieee8021xSettings, &handles)
		if rc != utils.Success {
			service.RollbackAddedItems(&handles)
			return rc
		}

	} else {
		wiFiEndpointSettings.PSKPassPhrase = wifiCfg.PskPassphrase
	}
	xmlMsg := service.amtMessages.WiFiPortConfigurationService.AddWiFiSettings(
		wiFiEndpointSettings,
		ieee8021xSettings,
		"WiFi Endpoint 0",
		handles.clientCertHandle,
		handles.rootCertHandle)
	var addWifiSettingsRsp wifiportconfiguration.AddWiFiSettingsResponse
	rc := service.PostAndUnmarshal(xmlMsg, &addWifiSettingsRsp)
	if rc != utils.Success {
		service.RollbackAddedItems(&handles)
		return rc
	}
	rc = utils.ReturnCode(addWifiSettingsRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue)
	if rc != 0 {
		service.RollbackAddedItems(&handles)
		log.Errorf("AddWiFiSettings_OUTPUT.ReturnValue: %d", rc)
		return utils.AmtPtStatusCodeBase + rc
	}
	return utils.Success
}

func (service *ProvisioningService) ProcessIeee8012xConfig(profileName string, settings *models.IEEE8021xSettings, handles *Handles) utils.ReturnCode {

	// find the matching configuration
	var ieee8021xConfig config.Ieee8021xConfig
	var found bool
	for _, curCfg := range service.flags.LocalConfig.Ieee8021xConfigs {
		if curCfg.ProfileName == profileName {
			ieee8021xConfig = curCfg
			found = true
			break
		}
	}
	if !found {
		log.Errorf("missing Ieee8021xConfig %s", profileName)
		return utils.MissingIeee8021xConfiguration
	}

	// translate from configuration to settings
	settings.ElementName = ieee8021xConfig.ProfileName
	settings.InstanceID = fmt.Sprintf("Intel(r) AMT: 8021X Settings %s", ieee8021xConfig.ProfileName)
	settings.AuthenticationProtocol = models.AuthenticationProtocol(ieee8021xConfig.AuthenticationProtocol)
	settings.Username = ieee8021xConfig.Username
	if settings.AuthenticationProtocol == models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 {
		settings.Password = ieee8021xConfig.Password
	}

	// add key and certs
	var rc utils.ReturnCode
	if ieee8021xConfig.PrivateKey != "" {
		handles.privateKeyHandle, rc = service.AddPrivateKey(ieee8021xConfig.PrivateKey)
		if rc != utils.Success {
			return rc
		}
	}
	if ieee8021xConfig.ClientCert != "" {
		handles.clientCertHandle, rc = service.AddClientCert(ieee8021xConfig.ClientCert)
		if rc != utils.Success {
			return rc
		}
	}
	handles.rootCertHandle, rc = service.AddTrustedRootCert(ieee8021xConfig.CACert)
	return rc
}

func (service *ProvisioningService) EnableWifi() utils.ReturnCode {
	xmlMsg := service.amtMessages.WiFiPortConfigurationService.Get()
	var portCfgRsp wifiportconfiguration.Response
	rc := service.PostAndUnmarshal(xmlMsg, &portCfgRsp)
	if rc != utils.Success {
		return rc
	}

	// if local sync not enable, enable it
	if portCfgRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled == wifiportconfiguration.LocalSyncDisabled {

		portCfgRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = wifiportconfiguration.UnrestrictedSync
		xmlMsg = service.amtMessages.WiFiPortConfigurationService.Put(portCfgRsp.Body.WiFiPortConfigurationService)
		rc = service.PostAndUnmarshal(xmlMsg, &portCfgRsp)
		if rc != utils.Success {
			return rc
		}
		if portCfgRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled == 0 {
			log.Errorf("failed to enable wifi local profile synchronization")
			return utils.WiFiConfigurationFailed
		}
	}

	// always turn wifi on via state change request
	//   Enumeration 32769 - WiFi is enabled in S0 + Sx/AC
	xmlMsg = service.cimMessages.WiFiPort.RequestStateChange(32769)
	var stateChangeRsp wifi.RequestStateChangeResponse
	rc = service.PostAndUnmarshal(xmlMsg, &stateChangeRsp)
	if rc != utils.Success {
		return rc
	}
	rc = utils.ReturnCode(stateChangeRsp.Body.RequestStateChange_OUTPUT.ReturnValue)
	if rc != utils.Success {
		log.Errorf("AddWiFiSettings_OUTPUT.ReturnValue: %d", rc)
		return utils.AmtPtStatusCodeBase + rc
	}
	return utils.Success
}

type Handles struct {
	privateKeyHandle string
	clientCertHandle string
	rootCertHandle   string
}

func (service *ProvisioningService) RollbackAddedItems(handles *Handles) {
	if handles.privateKeyHandle != "" {
		log.Infof("rolling back private key %s", handles.privateKeyHandle)
		xmlMsg := service.amtMessages.PublicPrivateKeyPair.Delete(handles.privateKeyHandle)
		_, err := service.client.Post(xmlMsg)
		if err != nil {
			log.Errorf("failed deleting private key: %s", handles.privateKeyHandle)
		} else {
			log.Debugf("successfully deleted private key: %s", handles.privateKeyHandle)
		}
	}
	if handles.clientCertHandle != "" {
		log.Infof("rolling back client cert %s", handles.clientCertHandle)
		xmlMsg := service.amtMessages.PublicKeyCertificate.Delete(handles.clientCertHandle)
		_, err := service.client.Post(xmlMsg)
		if err != nil {
			log.Errorf("failed deleting client cert: %s", handles.clientCertHandle)
		} else {
			log.Debugf("successfully deleted client cert: %s", handles.clientCertHandle)
		}
	}
	if handles.rootCertHandle != "" {
		log.Infof("rolling back root cert %s", handles.rootCertHandle)
		xmlMsg := service.amtMessages.PublicKeyCertificate.Delete(handles.rootCertHandle)
		_, err := service.client.Post(xmlMsg)
		if err != nil {
			log.Errorf("failed deleting root cert: %s", handles.rootCertHandle)
		} else {
			log.Debugf("successfully deleted root cert: %s", handles.rootCertHandle)
		}
	}
}

func (service *ProvisioningService) AddTrustedRootCert(caCert string) (string, utils.ReturnCode) {
	// check if this has been added already
	for k, v := range service.handlesWithCerts {
		if v == caCert {
			return k, utils.Success
		}
	}
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddTrustedRootCertificate(caCert)
	var rspEnv publickey.Response
	rc := service.PostAndUnmarshal(xmlMsg, &rspEnv)
	if rc != utils.Success {
		return "", rc
	}
	rc = checkReturnValue(utils.ReturnCode(rspEnv.Body.AddTrustedRootCertificate_OUTPUT.ReturnValue), "root certificate")
	if rc != utils.Success {
		return "", rc
	}
	var handle string
	if len(rspEnv.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector) > 0 {
		handle = rspEnv.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value
	}
	service.handlesWithCerts[handle] = caCert
	return handle, utils.Success
}

func (service *ProvisioningService) AddClientCert(clientCert string) (string, utils.ReturnCode) {
	// check if this has been added already
	for k, v := range service.handlesWithCerts {
		if v == clientCert {
			return k, utils.Success
		}
	}
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddCertificate(clientCert)
	var rspEnv publickey.Response
	rc := service.PostAndUnmarshal(xmlMsg, &rspEnv)
	if rc != utils.Success {
		return "", rc
	}
	rc = checkReturnValue(utils.ReturnCode(rspEnv.Body.AddTrustedCertificate_OUTPUT.ReturnValue), "client certificate")
	if rc != utils.Success {
		return "", rc
	}
	var handle string
	if len(rspEnv.Body.AddTrustedCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector) > 0 {
		handle = rspEnv.Body.AddTrustedCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value
	}
	service.handlesWithCerts[handle] = clientCert
	return handle, utils.Success
}

func (service *ProvisioningService) AddPrivateKey(privateKey string) (string, utils.ReturnCode) {
	// check if this has been added already, but need the publik key of the pair
	for k, v := range service.handlesWithCerts {
		if v == privateKey {
			return k, utils.Success
		}
	}
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddKey([]byte(privateKey))
	var rspEnv publickey.Response
	rc := service.PostAndUnmarshal(xmlMsg, &rspEnv)
	if rc != utils.Success {
		return "", rc
	}
	rc = checkReturnValue(utils.ReturnCode(rspEnv.Body.AddKey_OUTPUT.ReturnValue), "private key")
	if rc != utils.Success {
		return "", rc
	}
	var handle string
	if len(rspEnv.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selector) > 0 {
		handle = rspEnv.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selector[0].Value
	}
	service.handlesWithCerts[handle] = privateKey
	return handle, utils.Success
}

func checkReturnValue(rc utils.ReturnCode, item string) utils.ReturnCode {
	if rc != common.PT_STATUS_SUCCESS {
		if rc == common.PT_STATUS_DUPLICATE {
			log.Errorf("%s already exists and must be removed before continuing", item)
			return utils.AmtPtStatusCodeBase + rc
		} else if rc == common.PT_STATUS_INVALID_CERT {
			log.Errorf("%s is invalid", item)
			return utils.AmtPtStatusCodeBase + rc
		} else {
			log.Errorf("%s non-zero return code: %d", item, rc)
			return utils.AmtPtStatusCodeBase + rc
		}
	}
	return utils.Success
}
