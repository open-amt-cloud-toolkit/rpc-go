//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	log "github.com/sirupsen/logrus"
	"os/exec"
	"rpc/pkg/utils"
)

func (n *RealOSNetworker) RenewDHCPLease() utils.ReturnCode {
	log.Debug("renewing DHCP lease")
	cmd := exec.Command("dhclient")
	err := cmd.Run()
	if err != nil {
		log.Error("Error renewing DHCP lease:", err)
		return utils.NetworkConfigurationFailed
	}
	return utils.Success
}
