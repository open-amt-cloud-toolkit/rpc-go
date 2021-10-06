//go:build amt
// +build amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package pthi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetGUID(t *testing.T) {
	pthi := PTHICommand{}
	err := pthi.heci.Init()
	defer pthi.Close()
	assert.NoError(t, err)
	result, err := pthi.GetUUID()

	assert.NoError(t, err)
	assert.NotEmpty(t, result)

}
