/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) SetMebx() (err error) {
	// Retrieve the current control mode from the AMT command interface.
	controlMode, err := service.amtCommand.GetControlMode()
	if err != nil {
		log.Error("Failed to get control mode:", err)
		return utils.AMTConnectionFailed
	}

	// Check if the control mode is ACM (Admin Control Mode)
	if controlMode != 2 { // If not in ACM, return an error.
		errMsg := "MEBx password can only be configured in ACM. Current device control mode: " + utils.InterpretControlMode(controlMode)
		log.Error(errMsg)
		return utils.SetMEBXPasswordFailed
	}

	// Set up MEBx with the provided password.
	response, err := service.interfacedWsmanMessage.SetupMEBX(service.config.Configure.MEBxPassword)
	log.Trace(response)
	if err != nil {
		log.Error("Failed to configure MEBx Password:", err)
		return err
	}

	log.Info("Successfully configured MEBx Password.")
	return nil
}
