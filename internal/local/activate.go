package local

import (
	"encoding/xml"
	"errors"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/general"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/ips/hostbasedsetup"
	log "github.com/sirupsen/logrus"
)

func (local *LocalConfiguration) ActivateCCM() {
	generalSettings, err := local.GetGeneralSettings()
	if err != nil {
		log.Error(err)
		return
	}
	_, err = local.HostBasedSetup(generalSettings.Body.AMTGeneralSettings.DigestRealm, local.config.Password)
	if err != nil {
		log.Error(err)
		return
	}
}

func (local *LocalConfiguration) GetGeneralSettings() (general.Response, error) {
	message := local.amtMessages.GeneralSettings.Get()
	response, err := local.client.Post(message)
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
func (local *LocalConfiguration) HostBasedSetup(digestRealm string, password string) (bool, error) {
	message := local.ipsMessages.HostBasedSetupService.Setup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password)
	response, err := local.client.Post(message)
	if err != nil {
		return false, err
	}
	var hostBasedSetupResponse hostbasedsetup.Response
	err = xml.Unmarshal([]byte(response), &hostBasedSetupResponse)
	if err != nil {
		return false, err
	}
	if hostBasedSetupResponse.Body.Setup_OUTPUT.ReturnValue != 0 {
		return false, errors.New("Unable to activate CCM, check to make sure the device is not alreacy activated")
	}
	return true, nil
}
