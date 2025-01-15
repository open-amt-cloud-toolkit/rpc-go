/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"github.com/rsdmike/rpc-go/v2/internal/flags"
	"github.com/rsdmike/rpc-go/v2/pkg/utils"

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

func (service *ProvisioningService) CheckAndEnableAMT(skipIPRenewal bool) (bool, error) {
	resp, err := service.amtCommand.GetChangeEnabled()
	tlsIsEnforced := false
	if err != nil {
		if err.Error() == "wait timeout while sending data" {
			log.Debug("Operation timed out while sending data. This may occur on systems with AMT version 11 and below.")
			return tlsIsEnforced, nil
		}
		log.Error(err)
		return tlsIsEnforced, utils.AMTConnectionFailed
	}
	if !resp.IsNewInterfaceVersion() {
		log.Debug("this AMT version does not support SetAmtOperationalState")
		return tlsIsEnforced, nil
	}
	if resp.IsTlsEnforcedOnLocalPorts() {
		tlsIsEnforced = true
		log.Debug("TLS is enforced on local ports")
	}
	if resp.IsAMTEnabled() {
		log.Debug("AMT is already enabled")
		return tlsIsEnforced, nil
	}
	err = service.EnableAMT()
	if err != nil {
		return tlsIsEnforced, err
	}
	if !skipIPRenewal {
		err := service.RenewIP()
		return tlsIsEnforced, err
	}
	return tlsIsEnforced, nil
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
