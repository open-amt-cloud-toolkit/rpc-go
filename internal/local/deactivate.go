package local

import (
	"rpc/pkg/utils"

	"github.com/sirupsen/logrus"
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
			return utils.MissingOrIncorrectPassword
		}
	}
	service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password, logrus.GetLevel() == logrus.TraceLevel)
	_, err = service.interfacedWsmanMessage.Unprovision(1)
	if err != nil {
		log.Error("Status: Unable to deactivate ", err)
		return utils.UnableToDeactivate
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
