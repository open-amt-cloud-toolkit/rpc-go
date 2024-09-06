/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto/tls"
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
	// Deactivate based on the control mode
	switch controlMode {
	case 1: // CCMMode
		err = service.DeactivateCCM()
	case 2: // ACMMode
		err = service.DeactivateACM()
	default:
		log.Error("Deactivation failed. Device control mode: " + utils.InterpretControlMode(controlMode))
		return utils.UnableToDeactivate
	}

	if err != nil {
		log.Error("Deactivation failed.", err)
		return utils.UnableToDeactivate
	}

	log.Info("Status: Device deactivated")
	return nil
}

func (service *ProvisioningService) DeactivateACM() (err error) {
	if service.flags.Password == "" {
		err := service.flags.ReadPasswordFromUser()
		if err != nil {
			return utils.MissingOrIncorrectPassword
		}
	}
	service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password, false, logrus.GetLevel() == logrus.TraceLevel, &tls.Config{})
	_, err = service.interfacedWsmanMessage.Unprovision(1)
	if err != nil {
		log.Error("Status: Unable to deactivate ", err)
		return utils.UnableToDeactivate
	}
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
	return nil
}
