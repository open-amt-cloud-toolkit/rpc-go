package local

import (
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	log "github.com/sirupsen/logrus"
	"rpc/pkg/utils"
)

func (service *ProvisioningService) Configure() int {

	service.setupWsmanClient("admin", service.flags.Password)

	if service.flags.SubCommand == utils.SubCommandAddWifiSettings {
		err := service.Configure8021xWiFi()
		if err != nil {
			return utils.WiFiConfigurationFailed
		}
	}
	if len(service.flags.LocalConfig.WifiConfigs) > 0 {
		return service.ConfigureWiFi()
	}
	return utils.InvalidParameters
}

func (service *ProvisioningService) ConfigureWiFi() int {
	if result := service.EnableWifiOnAMT(); result != utils.Success {
		return result
	}
	// loop through the configurations and add them accordingly
	fmt.Println("loop through the configurations and add them accordingly")
	return utils.Success
}

func (service *ProvisioningService) EnableWifiOnAMT() int {

	fmt.Println("get the WiFiPortConfigurationService")
	//   context.xmlMessage = context.amt.WiFiPortConfigurationService.Get()
	//   wifiPortConfigurationService = post the message

	fmt.Println("if local sync not enable, enable it")
	// if wifiPortConfigurationService.localProfileSynchronizationEnabled == 0 {
	//   wifiPortConfigurationService.localProfileSynchronizationEnabled = 3
	//   result = post the message
	//   check result for errors
	// }

	fmt.Println("always turn wifi on")
	//   Enumeration 32769 - WiFi is enabled in S0 + Sx/AC
	//   msg = cim.WiFiPort.RequestStateChange(32769)
	//   result = post the message
	//   check result for errors

	return utils.Success
}

func (service *ProvisioningService) Configure8021xWiFi() error {
	privateKeyHandle, err := service.AddPrivateKey()
	if err != nil {
		return err
	}

	certHandle, err := service.AddClientCert()
	if err != nil {
		return err
	}

	rootHandle, err := service.AddTrustedRootCert()
	if err != nil {
		return err
	}

	err = service.AddWifiSettings(certHandle, rootHandle)
	if err != nil {
		log.Error("error adding wifi settings", err)
		err = service.RollbackAddedItems(certHandle, rootHandle, privateKeyHandle)
		if err != nil {
			log.Error("error rolling back added certificates", err)
		}
		return err
	}
	return nil
}

func (service *ProvisioningService) AddWifiSettings(certHandle string, rootHandle string) error {
	wifiEndpointSettings := models.WiFiEndpointSettings{
		ElementName:          service.config.Name,
		InstanceID:           fmt.Sprintf("Intel(r) AMT:WiFi Endpoint Settings %s", service.config.Name),
		SSID:                 service.config.SSID,
		Priority:             service.config.Priority,
		AuthenticationMethod: models.AuthenticationMethod(service.config.AuthenticationMethod),
		EncryptionMethod:     models.EncryptionMethod(service.config.EncryptionMethod),
	}
	ieee8021xSettings := &models.IEEE8021xSettings{
		ElementName:            service.config.Name,
		InstanceID:             fmt.Sprintf("Intel(r) AMT: 8021X Settings %s", service.config.Name),
		AuthenticationProtocol: models.AuthenticationProtocol(service.config.AuthenticationProtocol),
		Username:               service.config.Username,
	}

	addWiFiSettingsMessage := service.amtMessages.WiFiPortConfigurationService.AddWiFiSettings(wifiEndpointSettings, ieee8021xSettings, "WiFi Endpoint 0", certHandle, rootHandle)
	addWiFiSettingsResponse, err := service.client.Post(addWiFiSettingsMessage)
	if err != nil {
		return err
	}
	var gs publickey.Response
	err = xml.Unmarshal([]byte(addWiFiSettingsResponse), &gs)
	if err != nil {
		return err
	}
	return nil
}
func (service *ProvisioningService) RollbackAddedItems(certHandle, rootHandle, privateKeyHandle string) error {
	log.Debug("rolling back added keys and certificates")

	if privateKeyHandle != "" {
		deleteMessage := service.amtMessages.PublicPrivateKeyPair.Delete(privateKeyHandle)
		_, err := service.client.Post(deleteMessage)
		if err != nil {
			return err
		}
		log.Debug("successfully removed private key")
	}

	if certHandle != "" {
		deleteMessage := service.amtMessages.PublicKeyCertificate.Delete(certHandle)
		_, err := service.client.Post(deleteMessage)
		if err != nil {
			return err
		}
		log.Debug("successfully removed client certificate")
	}

	if rootHandle != "" {
		deleteMessage := service.amtMessages.PublicKeyCertificate.Delete(rootHandle)
		_, err := service.client.Post(deleteMessage)
		if err != nil {
			return err
		}
		log.Debug("successfully removed trusted root certificate")
	}

	return nil
}
func (service *ProvisioningService) AddTrustedRootCert() (string, error) {
	var gs publickey.Response
	addRootCertMessage := service.amtMessages.PublicKeyManagementService.AddTrustedRootCertificate(service.config.CACert)
	caCertResponse, err := service.client.Post(addRootCertMessage)
	if err != nil {
		return "", err
	}
	err = xml.Unmarshal([]byte(caCertResponse), &gs)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	fmt.Println(string(caCertResponse))

	shouldReturn, err := checkReturnValue(gs.Body.AddTrustedRootCertificate_OUTPUT.ReturnValue, "root certificate")
	if shouldReturn {
		return "", err
	}

	rootHandle := gs.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value

	return rootHandle, nil
}

func (service *ProvisioningService) AddClientCert() (string, error) {
	addCertMessage := service.amtMessages.PublicKeyManagementService.AddCertificate(service.config.ClientCert)
	clientCertResponse, err := service.client.Post(addCertMessage)
	if err != nil {
		return "", err
	}

	var gs publickey.Response
	err = xml.Unmarshal([]byte(clientCertResponse), &gs)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	shouldReturn, err := checkReturnValue(gs.Body.AddTrustedCertificate_OUTPUT.ReturnValue, "client certificate")
	if shouldReturn {
		return "", err
	}
	certHandle := gs.Body.AddTrustedCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selector[0].Value
	return certHandle, nil
}

func (service *ProvisioningService) AddPrivateKey() (handle string, err error) {
	message := service.amtMessages.PublicKeyManagementService.AddKey([]byte(service.config.PrivateKey))
	addKeyOutput, err := service.client.Post(message)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	var addKeyOutputStuff publickey.Response
	err = xml.Unmarshal([]byte(addKeyOutput), &addKeyOutputStuff)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	fmt.Println(string(addKeyOutput))
	shouldReturn, err := checkReturnValue(addKeyOutputStuff.Body.AddKey_OUTPUT.ReturnValue, "private key")
	if shouldReturn {
		return "", err
	}
	privateKeyHandle := addKeyOutputStuff.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selector[0].Value

	return privateKeyHandle, nil
}

func checkReturnValue(returnValue int, item string) (bool, error) {
	if returnValue != 0 {
		if returnValue == common.PT_STATUS_DUPLICATE {
			fmt.Printf("%s already exists", item)
			return true, errors.New("item already exists. You must remove it manually before continuing")
		} else if returnValue == common.PT_STATUS_INVALID_CERT {
			return true, fmt.Errorf("%s invalid cert", item)
		} else {
			return true, fmt.Errorf("non-zero return code: %d", returnValue)
		}
	}
	return false, nil
}
