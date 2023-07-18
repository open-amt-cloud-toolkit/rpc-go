package local

import (
	log "github.com/sirupsen/logrus"
	"rpc/pkg/utils"
)

func (service *ProvisioningService) Deactivate() int {

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

func (service *ProvisioningService) DeactivateACM() int {
	log.Error("local deactivation in Admin Control Mode not currently supported")
	return utils.DeactivationFailed
}

func (service *ProvisioningService) DeactivateCCM() int {
	status, err := service.amtCommand.Unprovision()
	if err != nil || status != 0 {
		log.Error(err)
		return utils.DeactivationFailed
	}
	log.Info("Status: Device deactivated.")
	return utils.Success
}
