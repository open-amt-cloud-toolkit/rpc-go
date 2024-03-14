/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"rpc/internal/flags"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) EnableAMT() error {
	log.Info("Enabling AMT")
	err := service.amtCommand.EnableAMT()
	if err != nil {
		log.Error("Failed to enable AMT ", err)
		return utils.AmtNotReady
	}
	return nil
}

func (service *ProvisioningService) CheckAndEnableAMT(skipIPRenewal bool) error {
	rsp, err := service.amtCommand.GetChangeEnabled()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}
	if !rsp.IsNewInterfaceVersion() {
		log.Debug("this AMT version does not support SetAmtOperationalState")
		return nil
	}
	if rsp.IsAMTEnabled() {
		log.Debug("AMT is already enabled")
		return nil
	}
	err = service.EnableAMT()
	if err != nil {
		return err
	}
	if !skipIPRenewal {
		err := service.RenewIP()
		return err
	}
	return nil
}

func (service *ProvisioningService) RenewIP() error {
	err := service.networker.RenewDHCPLease()
	if err != nil {
		return err
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		amtInfoOrig := service.flags.AmtInfo
		service.flags.AmtInfo = flags.AmtInfoFlags{
			DNS: true,
			Lan: true,
		}
		service.DisplayAMTInfo()
		service.flags.AmtInfo = amtInfoOrig
	}
	return nil
}
