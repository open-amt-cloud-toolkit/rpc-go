package local

import (
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	log "github.com/sirupsen/logrus"
	"regexp"
	"rpc/internal/config"
	"rpc/pkg/utils"
)

func (service *ProvisioningService) Configure() int {
	service.setupWsmanClient("admin", service.flags.Password)

	//if service.flags.SubCommand == utils.SubCommandAddWifiSettings {
	//	err := service.Configure8021xWiFi()
	//	if err != nil {
	//		return utils.WiFiConfigurationFailed
	//	}
	//}
	if len(service.flags.LocalConfig.WifiConfigs) > 0 {
		return service.ConfigureWiFi()
	}
	return utils.InvalidParameters
}

func (service *ProvisioningService) ConfigureWiFi() int {
	err := service.EnableWifi()
	if err != nil {
		log.Error(err)
		return utils.WiFiConfigurationFailed
	}
	lc := service.flags.LocalConfig
	var successes []string
	var failures []string
	for _, cfg := range lc.WifiConfigs {
		log.Info("configuring wifi profile: ", cfg.ProfileName)
		err = service.ProcessWifiConfig(&cfg)
		if err != nil {
			log.Error("failed configuring: ", cfg.ProfileName)
			log.Error(err)
			failures = append(failures, cfg.ProfileName)
		} else {
			log.Info("successfully configured: ", cfg.ProfileName)
			successes = append(successes, cfg.ProfileName)
		}
	}
	if len(failures) > 0 {
		// TODO: return the new warnings code
		return utils.WiFiConfigurationFailed
	}
	return utils.Success
}

func (service *ProvisioningService) ProcessWifiConfig(wifiCfg *config.WifiConfig) error {

	// profile names can only be alphanumeric (not even dashes)
	var reAlphaNum = regexp.MustCompile("[^a-zA-Z0-9]+")
	if reAlphaNum.MatchString(wifiCfg.ProfileName) {
		return fmt.Errorf("invalid wifi profile name: %s (only alphanumeric allowed)", wifiCfg.ProfileName)
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
		err := service.ProcessIeee8012xConfig(wifiCfg.Ieee8021xProfileName, ieee8021xSettings, &handles)
		if err != nil {
			service.RollbackAddedItems(&handles)
			return err
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
	xmlRsp, err := service.client.Post(xmlMsg)
	if err != nil {
		service.RollbackAddedItems(&handles)
		return err
	}
	var addWifiSettingsRsp wifiportconfiguration.AddWiFiSettingsResponse
	err = xml.Unmarshal(xmlRsp, &addWifiSettingsRsp)
	if err != nil {
		service.RollbackAddedItems(&handles)
		return err
	}
	returnValue := addWifiSettingsRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue
	if returnValue != 0 {
		return fmt.Errorf("AddWiFiSettings_OUTPUT.ReturnValue: %d", returnValue)
	}
	return nil
}

func (service *ProvisioningService) ProcessIeee8012xConfig(profileName string, settings *models.IEEE8021xSettings, handles *Handles) error {

	// find the matching configuration
	var ieee8021xConfig *config.Ieee8021xConfig
	for _, curCfg := range service.flags.LocalConfig.Ieee8021xConfigs {
		if curCfg.ProfileName == profileName {
			ieee8021xConfig = &curCfg
		}
	}
	if ieee8021xConfig == nil {
		errMsg := fmt.Sprintf("missing Ieee8021xConfig %s", profileName)
		return errors.New(errMsg)
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
	var err error
	handles.privateKeyHandle, err = service.AddPrivateKey(ieee8021xConfig.PrivateKey)
	if err != nil {
		return err
	}
	handles.clientCertHandle, err = service.AddClientCert(ieee8021xConfig.ClientCert)
	if err != nil {
		return err
	}
	handles.rootCertHandle, err = service.AddTrustedRootCert(ieee8021xConfig.CACert)
	if err != nil {
		return err
	}
	return nil
}

func (service *ProvisioningService) EnableWifi() error {
	xmlMsg := service.amtMessages.WiFiPortConfigurationService.Get()
	xmlRsp, err := service.client.Post(xmlMsg)
	if err != nil {
		return err
	}
	var wifiPortConfigResponse wifiportconfiguration.PortConfigurationResponse
	err = xml.Unmarshal(xmlRsp, &wifiPortConfigResponse)
	if err != nil {
		return err
	}

	// pcs := wifiPortConfigResponse.Body.WiFiPortConfigurationService

	// if local sync not enable, enable it
	if wifiPortConfigResponse.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled == wifiportconfiguration.LocalSyncDisabled {
		wifiPortConfigResponse.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = wifiportconfiguration.UnrestrictedSync
		xmlMsg = service.amtMessages.WiFiPortConfigurationService.Put(wifiPortConfigResponse.Body.WiFiPortConfigurationService)
		// not sure why it's accepted to not check the response for success code? this is what RPS does also
		// no response struct in wsmang messages
		xmlRsp, err = service.client.Post(xmlMsg)
		if err != nil {
			return err
		}
		err = xml.Unmarshal(xmlRsp, &wifiPortConfigResponse)
		if err != nil {
			return err
		}
		//pcs = wifiPortConfigResponse.Body.WiFiPortConfigurationService
		if wifiPortConfigResponse.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled == 0 {
			return errors.New("failed to enable wifi local profile synchronization")
		}
	}

	// always turn wifi on via state change request
	//   Enumeration 32769 - WiFi is enabled in S0 + Sx/AC
	xmlMsg = service.cimMessages.WiFiPort.RequestStateChange(32769)
	xmlRsp, err = service.client.Post(xmlMsg)
	if err != nil {
		return err
	}
	var stateChangeRsp wifi.RequestStateChangeResponse
	err = xml.Unmarshal(xmlRsp, &stateChangeRsp)
	if err != nil {
		return err
	}
	returnValue := stateChangeRsp.Body.RequestStateChange_OUTPUT.ReturnValue
	if returnValue != 0 {
		return fmt.Errorf("AddWiFiSettings_OUTPUT.ReturnValue: %d", returnValue)
	}

	return nil
}

type Handles struct {
	privateKeyHandle string
	clientCertHandle string
	rootCertHandle   string
}

func (service *ProvisioningService) RollbackAddedItems(handles *Handles) {
	log.Debug("rolling back added keys and certificates")

	if handles.privateKeyHandle != "" {
		deleteMessage := service.amtMessages.PublicPrivateKeyPair.Delete(handles.privateKeyHandle)
		_, err := service.client.Post(deleteMessage)
		if err != nil {
			log.Error(err)
		} else {
			log.Debug("successfully deleted private key")
		}
	}

	if handles.clientCertHandle != "" {
		deleteMessage := service.amtMessages.PublicKeyCertificate.Delete(handles.clientCertHandle)
		_, err := service.client.Post(deleteMessage)
		if err != nil {
			log.Error(err)
		} else {
			log.Debug("successfully deleted client certificate")
		}
	}

	if handles.rootCertHandle != "" {
		deleteMessage := service.amtMessages.PublicKeyCertificate.Delete(handles.rootCertHandle)
		_, err := service.client.Post(deleteMessage)
		if err != nil {
			log.Error(err)
		} else {
			log.Debug("successfully deleted root certificate")
		}
	}
}

func (service *ProvisioningService) AddTrustedRootCert(caCert string) (string, error) {
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddTrustedRootCertificate(caCert)
	xmlRsp, err := service.client.Post(xmlMsg)
	if err != nil {
		return "", err
	}
	var pkResponse publickey.Response
	err = xml.Unmarshal(xmlRsp, &pkResponse)
	if err != nil {
		return "", err
	}
	err = checkReturnValue(pkResponse.Body.AddTrustedRootCertificate_OUTPUT.ReturnValue, "root certificate")
	if err != nil {
		return "", err
	}
	handle := pkResponse.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value
	return handle, nil
}

func (service *ProvisioningService) AddClientCert(clientCert string) (string, error) {
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddCertificate(clientCert)
	xmlRsp, err := service.client.Post(xmlMsg)
	if err != nil {
		return "", err
	}
	var pkResponse publickey.Response
	err = xml.Unmarshal(xmlRsp, &pkResponse)
	if err != nil {
		return "", err
	}
	err = checkReturnValue(pkResponse.Body.AddTrustedCertificate_OUTPUT.ReturnValue, "client certificate")
	if err != nil {
		return "", err
	}
	handle := pkResponse.Body.AddTrustedCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value
	return handle, nil
}

func (service *ProvisioningService) AddPrivateKey(privateKey string) (string, error) {
	xmlMsg := service.amtMessages.PublicKeyManagementService.AddKey([]byte(privateKey))
	xmlRsp, err := service.client.Post(xmlMsg)
	if err != nil {
		return "", err
	}
	var pkResponse publickey.Response
	err = xml.Unmarshal(xmlRsp, &pkResponse)
	if err != nil {
		return "", err
	}
	err = checkReturnValue(pkResponse.Body.AddKey_OUTPUT.ReturnValue, "private key")
	if err != nil {
		return "", err
	}
	handle := pkResponse.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selector[0].Value
	return handle, nil
}

func checkReturnValue(returnValue int, item string) error {
	if returnValue != 0 {
		if returnValue == common.PT_STATUS_DUPLICATE {
			return fmt.Errorf("%s already exists and must be removed before continuing", item)
		} else if returnValue == common.PT_STATUS_INVALID_CERT {
			return fmt.Errorf("%s is invalid", item)
		} else {
			return fmt.Errorf("%s non-zero return code: %d", item, returnValue)
		}
	}
	return nil
}
