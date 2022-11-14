//go:build windows && amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestInit(t *testing.T) {
	h := Driver{}
	err := h.Init()
	assert.NoError(t, err)
	guid, _ := windows.GUIDFromString("{E2D1FF34-3458-49A9-88DA-8E6915CE9BE5}")
	pthiguid, _ := windows.GUIDFromString("{12F80028-B4B7-4B2D-ACA8-46E0FF65814C}")

	assert.Equal(t, h.GUID, guid)
	assert.Equal(t, h.PTHIGUID, pthiguid)
}

func TestFindDevices(t *testing.T) {
	h := Driver{}
	err := h.Init()
	assert.NoError(t, err)
}
