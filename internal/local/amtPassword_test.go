/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChangeAMTPassword(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandConfigure
	f.SubCommand = utils.SubCommandChangeAMTPassword

	t.Run("should return Success", func(t *testing.T) {
		f.ControlMode = 1
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)
	})
}
