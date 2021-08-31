/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeciInit(t *testing.T) {
	h := Heci{}
	err := h.HeciInit()
	assert.Error(t, err)
}

// func TestHeciRead(t *testing.T) {
// 	h := Heci{}
// 	err := h.SendMessage()
// 	assert.Error(t, err)
// }
