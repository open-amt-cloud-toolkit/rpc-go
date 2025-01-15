/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"testing"

	"github.com/rsdmike/rpc-go/v2/internal/flags"
	"github.com/rsdmike/rpc-go/v2/pkg/utils"

	"github.com/stretchr/testify/assert"
)

func TestChangeAMTPassword(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandConfigure
	f.SubCommand = utils.SubCommandChangeAMTPassword

	t.Run("should return Success", func(t *testing.T) {
		mockControlMode = 1
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)
	})
}
