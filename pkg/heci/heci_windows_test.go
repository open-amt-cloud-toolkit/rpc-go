//go:build windows
// +build windows
/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	h := Heci{}
	err := h.Init()
	assert.NoError(t, err)
}

func TestFindDevices(t *testing.T) {
	h := Heci{}
	err := h.Init()

	assert.NoError(t, err)
}
