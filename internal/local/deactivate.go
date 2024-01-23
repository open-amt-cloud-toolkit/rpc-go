package local

import (
	"errors"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Deactivate() (err error) {
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

func (service *ProvisioningService) DeactivateACM() (err error) {
	if service.flags.Password == "" {
		result, rc := service.flags.ReadPasswordFromUser()
		if !result || rc != nil {
			err = errors.New("Missing or Incorrect Password")
			return err
		}
	}
	service.setupWsmanClient("admin", service.flags.Password)
	response, err := service.wsmanMessages.AMT.SetupAndConfigurationService.Unprovision(1)
	if err != nil {
		log.Error("Status: Unable to deactivate ", err)
		return utils.UnableToDeactivate
	}
	if response.Body.Unprovision_OUTPUT.ReturnValue != 0 {
		log.Error("Status: Failed to deactivate. ReturnValue: ", response.Body.Unprovision_OUTPUT.ReturnValue)
		return utils.DeactivationFailed
	}
	log.Info("Status: Device deactivated in ACM.")
	return nil
}

func (service *ProvisioningService) DeactivateCCM() (err error) {
	if service.flags.Password != "" {
		log.Warn("Password not required for CCM deactivation")
	}
	status, err := service.amtCommand.Unprovision()
	if err != nil || status != 0 {
		log.Error("Status: Failed to deactivate ", err)
		return utils.DeactivationFailed
	}
	log.Info("Status: Device deactivated.")
	return nil
}
