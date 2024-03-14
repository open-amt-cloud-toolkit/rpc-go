//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"os"
	"strings"
)

func (amt AMTCommand) GetOSDNSSuffix() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	splitName := strings.SplitAfterN(hostname, ".", 2)
	if len(splitName) == 2 {
		return splitName[1], nil
	}
	return hostname, err
}
