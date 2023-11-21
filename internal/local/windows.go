//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package local

import (
	"os/exec"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (n *RealOSNetworker) RenewDHCPLease() utils.ReturnCode {
	log.Debug("renewing DHCP lease")
	cmd := exec.Command("ipconfig", "/renew")
	err := cmd.Run()
	if err != nil {
		log.Error("Error renewing DHCP lease:", err)
		return utils.NetworkConfigurationFailed
	}
	return utils.Success
}
