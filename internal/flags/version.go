/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"rpc/pkg/utils"
)

func (f *Flags) handleVersionCommand() error {
	if err := f.versionCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}
	// runs locally
	f.Local = true
	return nil
}
