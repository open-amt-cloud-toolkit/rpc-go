//go:build amt
// +build amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package amt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetGUID(t *testing.T) {
	amt := Command{}
	result, err := amt.GetUUIDV2()
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestGetControlmode(t *testing.T) {
	amt := Command{}
	result, err := amt.GetControlModeV2()
	assert.NoError(t, err)
	assert.NotEqual(t, -1, result)
}
