/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

// import (
// 	"rpc/internal/flags"
// 	"rpc/pkg/utils"
// 	"testing"

// 	"github.com/stretchr/testify/assert"
// )

// func TestDisplayVersion(t *testing.T) {
// 	f := &flags.Flags{}
// 	f.Command = utils.CommandVersion

// 	t.Run("should return Success", func(t *testing.T) {
// 		lps := setupService(f)
// 		err := lps.DisplayVersion()
// 		assert.NoError(t, err)
// 		assert.Equal(t, nil, err)
// 	})

// 	t.Run("should return Success with json output", func(t *testing.T) {
// 		f.JsonOutput = true
// 		lps := setupService(f)
// 		err := lps.DisplayVersion()
// 		assert.NoError(t, err)
// 		assert.Equal(t, nil, err)
// 		f.JsonOutput = false
// 	})

// }
