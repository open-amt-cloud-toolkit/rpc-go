package local

import (
	"encoding/xml"
	"errors"
	"fmt"
	"rpc/internal/config"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/ips"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman"

	log "github.com/sirupsen/logrus"
)

type LocalConfiguration struct {
	client      *wsman.Client
	config      config.Config
	amtMessages amt.Messages
	ipsMessages ips.Messages
}

func NewLocalConfiguration(config config.Config, client *wsman.Client) LocalConfiguration {
	return LocalConfiguration{
		client:      client,
		config:      config,
		amtMessages: amt.NewMessages(),
		ipsMessages: ips.NewMessages(),
	}

}

func (local *LocalConfiguration) Configure8021xWiFi() error {
	privateKeyHandle, err := local.AddPrivateKey()
	if err != nil {
		return err
	}

	certHandle, err := local.AddClientCert()
	if err != nil {
		return err
	}

	rootHandle, err := local.AddTrustedRootCert()
	if err != nil {
		return err
	}

	err = local.AddWifiSettings(certHandle, rootHandle)
	if err != nil {
		log.Error("error adding wifi settings", err)
		err = local.RollbackAddedItems(certHandle, rootHandle, privateKeyHandle)
		if err != nil {
			log.Error("error rolling back added certificates", err)
		}
		return err
	}
	return nil
}

func (local *LocalConfiguration) AddWifiSettings(certHandle string, rootHandle string) error {
	wifiEndpointSettings := models.WiFiEndpointSettings{
		ElementName:          local.config.Name,
		InstanceID:           fmt.Sprintf("Intel(r) AMT:WiFi Endpoint Settings %s", local.config.Name),
		SSID:                 local.config.SSID,
		Priority:             local.config.Priority,
		AuthenticationMethod: models.AuthenticationMethod(local.config.AuthenticationMethod),
		EncryptionMethod:     models.EncryptionMethod(local.config.EncryptionMethod),
	}
	ieee8021xSettings := &models.IEEE8021xSettings{
		ElementName:            local.config.Name,
		InstanceID:             fmt.Sprintf("Intel(r) AMT: 8021X Settings %s", local.config.Name),
		AuthenticationProtocol: models.AuthenticationProtocol(local.config.AuthenticationProtocol),
		Username:               local.config.Username,
	}

	addWiFiSettingsMessage := local.amtMessages.WiFiPortConfigurationService.AddWiFiSettings(wifiEndpointSettings, ieee8021xSettings, "WiFi Endpoint 0", certHandle, rootHandle)
	addWiFiSettingsResponse, err := local.client.Post(addWiFiSettingsMessage)
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
func (local *LocalConfiguration) RollbackAddedItems(certHandle, rootHandle, privateKeyHandle string) error {
	log.Debug("rolling back added keys and certificates")

	if privateKeyHandle != "" {
		deleteMessage := local.amtMessages.PublicPrivateKeyPair.Delete(privateKeyHandle)
		_, err := local.client.Post(deleteMessage)
		if err != nil {
			return err
		}
		log.Debug("successfully removed private key")
	}

	if certHandle != "" {
		deleteMessage := local.amtMessages.PublicKeyCertificate.Delete(certHandle)
		_, err := local.client.Post(deleteMessage)
		if err != nil {
			return err
		}
		log.Debug("successfully removed client certificate")
	}

	if rootHandle != "" {
		deleteMessage := local.amtMessages.PublicKeyCertificate.Delete(rootHandle)
		_, err := local.client.Post(deleteMessage)
		if err != nil {
			return err
		}
		log.Debug("successfully removed trusted root certificate")
	}

	return nil
}
func (local *LocalConfiguration) AddTrustedRootCert() (string, error) {
	var gs publickey.Response
	addRootCertMessage := local.amtMessages.PublicKeyManagementService.AddTrustedRootCertificate(local.config.CACert)
	caCertResponse, err := local.client.Post(addRootCertMessage)
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

func (local *LocalConfiguration) AddClientCert() (string, error) {
	addCertMessage := local.amtMessages.PublicKeyManagementService.AddCertificate(local.config.ClientCert)
	clientCertResponse, err := local.client.Post(addCertMessage)
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

func (local *LocalConfiguration) AddPrivateKey() (handle string, err error) {
	message := local.amtMessages.PublicKeyManagementService.AddKey([]byte(local.config.PrivateKey))
	addKeyOutput, err := local.client.Post(message)
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
