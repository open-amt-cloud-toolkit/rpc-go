/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreatePayloadNoDNSSuffix(t *testing.T) {
	result, err := createPayload("")
	assert.NotEmpty(t, result.Build)
	assert.NoError(t, err)
}
func TestCreatePayloadWithDNSSuffix(t *testing.T) {
	result, err := createPayload("vprodemo.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, result.Build)
}
func TestCreateActivationRequestNoDNSSuffix(t *testing.T) {
	result, err := CreateActivationRequest("method", "")
	assert.NoError(t, err)
	assert.Equal(t, "method", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.Equal(t, ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, ProjectVer, result.AppVersion)
}
func TestCreateActivationRequestWithDNSSuffix(t *testing.T) {
	result, err := CreateActivationRequest("method", "vprodemo.com")
	assert.NoError(t, err)
	assert.Equal(t, "method", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.Equal(t, ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, ProjectVer, result.AppVersion)
}

func TestCreateActivationResponse(t *testing.T) {
	result, err := CreateActivationResponse([]byte(""))
	assert.NoError(t, err)
	assert.Equal(t, "response", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.Equal(t, ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, ProjectVer, result.AppVersion)

}
