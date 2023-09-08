package local

import (
	"fmt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"
	"regexp"
	"rpc/internal/config"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Configure() int {
	service.setupWsmanClient("admin", service.flags.Password)

	if service.flags.SubCommand == utils.SubCommandAddWifiSettings {
		return service.AddWifiSettings()
	}
	return utils.IncorrectCommandLineParameters
}

func (service *ProvisioningService) AddWifiSettings() int {
	// start with fresh map
	service.handlesWithCerts = make(map[string]string)

	// PruneWifiConfigs is best effort
	// it will log error messages, but doesn't stop the configuration flow
	service.PruneWifiConfigs()
	resultCode := service.EnableWifi()
	if resultCode != utils.Success {
		return resultCode
	}
	return service.ProcessWifiConfigs()
}

func (service *ProvisioningService) PruneWifiConfigs() int {
	// get these handles BEFORE deleting the wifi profiles
	certHandles, keyPairHandles := service.GetWifiIeee8021xCerts()

	var pullRspEnv wifi.PullResponseEnvelope
	resultCode := service.EnumPullUnmarshal(
		service.cimMessages.WiFiEndpointSettings.Enumerate,
		service.cimMessages.WiFiEndpointSettings.Pull,
		&pullRspEnv,
	)
	if resultCode != utils.Success {
		return resultCode
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
		resultCode := service.DeletePublicCert(handle)
		if resultCode != utils.Success {
			failedCertHandles = append(failedCertHandles, handle)
		} else {
			delete(service.handlesWithCerts, handle)
		}
	}
	for _, handle := range keyPairHandles {
		resultCode := service.DeletePublicPrivateKeyPair(handle)
		if resultCode != utils.Success {
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
	credentials, resultCode := service.GetCredentialRelationships()
	if resultCode != utils.Success {
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

func (service *ProvisioningService) ProcessWifiConfigs() int {
	lc := service.flags.LocalConfig
	var successes []string
	var failures []string
	for _, cfg := range lc.WifiConfigs {
		log.Info("configuring wifi profile: ", cfg.ProfileName)
		resultCode := service.ProcessWifiConfig(&cfg)
		if resultCode != utils.Success {
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

func (service *ProvisioningService) ProcessWifiConfig(wifiCfg *config.WifiConfig) int {

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
		resultCode := service.ProcessIeee8012xConfig(wifiCfg.Ieee8021xProfileName, ieee8021xSettings, &handles)
		if resultCode != utils.Success {
			service.RollbackAddedItems(&handles)
			return resultCode
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
	resultCode := service.PostAndUnmarshal(xmlMsg, &addWifiSettingsRsp)
	if resultCode != utils.Success {
		service.RollbackAddedItems(&handles)
		return resultCode
	}
	returnValue := addWifiSettingsRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue
	if returnValue != 0 {
		service.RollbackAddedItems(&handles)
		log.Errorf("AddWiFiSettings_OUTPUT.ReturnValue: %d", returnValue)
		return utils.AmtPtStatusCodeBase + returnValue
	}
	return utils.Success
}

func (service *ProvisioningService) ProcessIeee8012xConfig(profileName string, settings *models.IEEE8021xSettings, handles *Handles) int {

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
	var resultCode int
	if ieee8021xConfig.PrivateKey != "" {
		handles.privateKeyHandle, resultCode = service.AddPrivateKey(ieee8021xConfig.PrivateKey)
		if resultCode != utils.Success {
			return resultCode
		}
	}
	if ieee8021xConfig.ClientCert != "" {
		handles.clientCertHandle, resultCode = service.AddClientCert(ieee8021xConfig.ClientCert)
		if resultCode != utils.Success {
			return resultCode
		}
	}
	handles.rootCertHandle, resultCode = service.AddTrustedRootCert(ieee8021xConfig.CACert)
	return resultCode
}

func (service *ProvisioningService) EnableWifi() int {
	xmlMsg := service.amtMessages.WiFiPortConfigurationService.Get()
	var portCfgRsp wifiportconfiguration.Response
	resultCode := service.PostAndUnmarshal(xmlMsg, &portCfgRsp)
	if resultCode != utils.Success {
		return resultCode
	}

	// if local sync not enable, enable it
	if portCfgRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled == wifiportconfiguration.LocalSyncDisabled {

		portCfgRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = wifiportconfiguration.UnrestrictedSync
		xmlMsg = service.amtMessages.WiFiPortConfigurationService.Put(portCfgRsp.Body.WiFiPortConfigurationService)
		resultCode = service.PostAndUnmarshal(xmlMsg, &portCfgRsp)
		if resultCode != utils.Success {
			return resultCode
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
	resultCode = service.PostAndUnmarshal(xmlMsg, &stateChangeRsp)
	if resultCode != utils.Success {
		return resultCode
	}
	returnValue := stateChangeRsp.Body.RequestStateChange_OUTPUT.ReturnValue
	if returnValue != 0 {
		log.Errorf("AddWiFiSettings_OUTPUT.ReturnValue: %d", returnValue)
		return utils.AmtPtStatusCodeBase + returnValue
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
		log.Trace(xmlMsg)
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
		log.Trace(xmlMsg)
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
		log.Trace(xmlMsg)
		_, err := service.client.Post(xmlMsg)
		if err != nil {
			log.Errorf("failed deleting root cert: %s", handles.rootCertHandle)
		} else {
			log.Debugf("successfully deleted root cert: %s", handles.rootCertHandle)
		}
	}
}

func (service *ProvisioningService) AddTrustedRootCert(caCert string) (string, int) {
	// check if this has been added already
	for k, v := range service.handlesWithCerts {
		if v == caCert {
			return k, utils.Success
		}
	}
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddTrustedRootCertificate(caCert)
	var rspEnv publickey.Response
	resultCode := service.PostAndUnmarshal(xmlMsg, &rspEnv)
	if resultCode != utils.Success {
		return "", resultCode
	}
	resultCode = checkReturnValue(rspEnv.Body.AddTrustedRootCertificate_OUTPUT.ReturnValue, "root certificate")
	if resultCode != utils.Success {
		return "", resultCode
	}
	var handle string
	if len(rspEnv.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector) > 0 {
		handle = rspEnv.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value
	}
	service.handlesWithCerts[handle] = caCert
	return handle, utils.Success
}

func (service *ProvisioningService) AddClientCert(clientCert string) (string, int) {
	// check if this has been added already
	for k, v := range service.handlesWithCerts {
		if v == clientCert {
			return k, utils.Success
		}
	}
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddCertificate(clientCert)
	var rspEnv publickey.Response
	resultCode := service.PostAndUnmarshal(xmlMsg, &rspEnv)
	if resultCode != utils.Success {
		return "", resultCode
	}
	resultCode = checkReturnValue(rspEnv.Body.AddTrustedCertificate_OUTPUT.ReturnValue, "client certificate")
	if resultCode != utils.Success {
		return "", resultCode
	}
	var handle string
	if len(rspEnv.Body.AddTrustedCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector) > 0 {
		handle = rspEnv.Body.AddTrustedCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value
	}
	service.handlesWithCerts[handle] = clientCert
	return handle, utils.Success
}

func (service *ProvisioningService) AddPrivateKey(privateKey string) (string, int) {
	// check if this has been added already, but need the publik key of the pair
	for k, v := range service.handlesWithCerts {
		if v == privateKey {
			return k, utils.Success
		}
	}
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddKey([]byte(privateKey))
	var rspEnv publickey.Response
	resultCode := service.PostAndUnmarshal(xmlMsg, &rspEnv)
	if resultCode != utils.Success {
		return "", resultCode
	}
	resultCode = checkReturnValue(rspEnv.Body.AddKey_OUTPUT.ReturnValue, "private key")
	if resultCode != utils.Success {
		return "", resultCode
	}
	var handle string
	if len(rspEnv.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selector) > 0 {
		handle = rspEnv.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selector[0].Value
	}
	service.handlesWithCerts[handle] = privateKey
	return handle, utils.Success
}

func checkReturnValue(returnValue int, item string) int {
	if returnValue != common.PT_STATUS_SUCCESS {
		if returnValue == common.PT_STATUS_DUPLICATE {
			log.Errorf("%s already exists and must be removed before continuing", item)
			return utils.AmtPtStatusCodeBase + returnValue
		} else if returnValue == common.PT_STATUS_INVALID_CERT {
			log.Errorf("%s is invalid", item)
			return utils.AmtPtStatusCodeBase + returnValue
		} else {
			log.Errorf("%s non-zero return code: %d", item, returnValue)
			return utils.AmtPtStatusCodeBase + returnValue
		}
	}
	return utils.Success
}
