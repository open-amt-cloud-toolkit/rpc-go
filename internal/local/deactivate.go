package local

import (
	"encoding/xml"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/setupandconfiguration"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Deactivate() utils.ReturnCode {

	controlMode, err := service.amtCommand.GetControlMode()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}
	if controlMode == 1 {
		return service.DeactivateCCM()
	} else if controlMode == 2 {
		return service.DeactivateACM()
	}
	log.Error("Deactivation failed. Device control mode: " + utils.InterpretControlMode(controlMode))
	return utils.UnableToDeactivate
}

func (service *ProvisioningService) DeactivateACM() utils.ReturnCode {
	if service.flags.Password == "" {
		if _, rc := service.flags.ReadPasswordFromUser(); rc != utils.Success {
			return rc
		}
	}
	service.setupWsmanClient("admin", service.flags.Password)
	msg := service.amtMessages.SetupAndConfigurationService.Unprovision(1)
	response, err := service.client.Post(msg)
	if err != nil {
		log.Error("Status: Unable to deactivate ", err)
		return utils.UnableToDeactivate
	}
	var setupResponse setupandconfiguration.UnprovisionResponse
	err = xml.Unmarshal([]byte(response), &setupResponse)
	if err != nil {
		log.Error("Status: Failed to deactivate ", err)
		return utils.DeactivationFailed
	}
	if setupResponse.Body.Unprovision_OUTPUT.ReturnValue != 0 {
		log.Error("Status: Failed to deactivate. ReturnValue: ", setupResponse.Body.Unprovision_OUTPUT.ReturnValue)
		return utils.DeactivationFailed
	}
	log.Info("Status: Device deactivated in ACM.")
	return utils.Success
}

func (service *ProvisioningService) DeactivateCCM() utils.ReturnCode {
	if service.flags.Password != "" {
		log.Warn("Password not required for CCM deactivation")
	}
	status, err := service.amtCommand.Unprovision()
	if err != nil || status != 0 {
		log.Error("Status: Failed to deactivate ", err)
		return utils.DeactivationFailed
	}
	log.Info("Status: Device deactivated.")
	return utils.Success
}
