/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"errors"
	"net/url"

	"github.com/rsdmike/rpc-go/v2/pkg/utils"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Configure() (err error) {
	// Check if the device is already activated
	controlMode, err := service.amtCommand.GetControlMode()
	if err != nil {
		return utils.AMTConnectionFailed
	}
	if controlMode == 0 {
		log.Error("Device is not activated to configure. Please activate the device first.")
		return utils.UnableToConfigure
	}
	service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password, logrus.GetLevel() == logrus.TraceLevel)

	switch service.flags.SubCommand {
	case utils.SubCommandAddEthernetSettings, utils.SubCommandWired:
		return service.AddEthernetSettings()
	case utils.SubCommandAddWifiSettings, utils.SubCommandWireless:
		return service.AddWifiSettings()
	case utils.SubCommandEnableWifiPort:
		return service.EnableWifiPort(true)
	case utils.SubCommandSetMEBx:
		if controlMode != 2 {
			log.Error("Device needs to be in admin control mode to set MEBx password.")
			return utils.UnableToConfigure
		}
		return service.SetMebx()
	case utils.SubCommandConfigureTLS:
		return service.ConfigureTLS()
	case utils.SubCommandSyncClock:
		return service.SynchronizeTime()
	case utils.SubCommandChangeAMTPassword:
		return service.ChangeAMTPassword()
	case utils.SubCommandSetAMTFeatures:
		if controlMode != 2 {
			log.Error("Device needs to be in admin control mode to configure AMT features.")
			return utils.UnableToConfigure
		}
		return service.SetAMTFeatures()
	default:
	}
	return utils.IncorrectCommandLineParameters
}

func (service *ProvisioningService) EnableWifiPort(enableSync bool) (err error) {
	err = service.interfacedWsmanMessage.EnableWiFi(enableSync)
	if err != nil {
		log.Error("Failed to enable wifi port and local profile synchronization.")
		return
	}
	log.Info("Successfully enabled wifi port and local profile synchronization.")
	return
}

func (service *ProvisioningService) ValidateURL(u string) error {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return err
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return errors.New("url is missing scheme or host")
	}

	return nil
}
