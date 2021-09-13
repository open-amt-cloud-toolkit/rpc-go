/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package mps

import (
	"rpc/internal/amt"
	"rpc/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Mock the AMT Hardware
type MockAMT struct{}

var mebxDNSSuffix string

func (c MockAMT) Initialize() (bool, error) {
	return true, nil
}
func (c MockAMT) GetVersionDataFromME(key string) (string, error) { return "Version", nil }
func (c MockAMT) GetUUID() (string, error)                        { return "123-456-789", nil }
func (c MockAMT) GetUUIDV2() (string, error)                      { return "", nil }
func (c MockAMT) GetControlMode() (int, error)                    { return 1, nil }
func (c MockAMT) GetControlModeV2() (int, error)                  { return 1, nil }
func (c MockAMT) GetOSDNSSuffix() (string, error)                 { return "osdns", nil }
func (c MockAMT) GetDNSSuffix() (string, error)                   { return mebxDNSSuffix, nil }
func (c MockAMT) GetCertificateHashes() ([]amt.CertHashEntry, error) {
	return []amt.CertHashEntry{}, nil
}
func (c MockAMT) GetRemoteAccessConnectionStatus() (amt.RemoteAccessStatus, error) {
	return amt.RemoteAccessStatus{}, nil
}
func (c MockAMT) GetLANInterfaceSettings(useWireless bool) (amt.InterfaceSettings, error) {
	return amt.InterfaceSettings{}, nil
}
func (c MockAMT) GetLocalSystemAccount() (amt.LocalSystemAccount, error) {
	return amt.LocalSystemAccount{Username: "Username", Password: "Password"}, nil
}

var p Payload

func (c MockAMT) InitiateLMS() {}

func init() {
	p = Payload{}
	p.amt = MockAMT{}

}
func TestCreatePayload(t *testing.T) {
	mebxDNSSuffix = "mebxdns"
	result, err := p.createPayload("")
	assert.Equal(t, "Version", result.Version)
	assert.Equal(t, "Version", result.Build)
	assert.Equal(t, "Version", result.SKU)
	assert.Equal(t, "123-456-789", result.UUID)
	assert.Equal(t, "Username", result.Username)
	assert.Equal(t, "Password", result.Password)
	assert.Equal(t, 1, result.CurrentMode)
	assert.NotEmpty(t, result.Hostname)
	assert.Equal(t, "mebxdns", result.FQDN)
	assert.Equal(t, utils.ClientName, result.Client)
	assert.Len(t, result.CertificateHashes, 0)
	assert.NoError(t, err)
}
func TestCreatePayloadWithOSDNSSuffix(t *testing.T) {
	mebxDNSSuffix = ""
	result, err := p.createPayload("")
	assert.NoError(t, err)
	assert.Equal(t, "osdns", result.FQDN)
}
func TestCreatePayloadWithDNSSuffix(t *testing.T) {

	result, err := p.createPayload("vprodemo.com")
	assert.NoError(t, err)
	assert.Equal(t, "vprodemo.com", result.FQDN)
}
func TestCreateActivationRequestNoDNSSuffix(t *testing.T) {

	result, err := p.CreateActivationRequest("method", "")
	assert.NoError(t, err)
	assert.Equal(t, "method", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.Equal(t, utils.ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, utils.ProjectVersion, result.AppVersion)
}
func TestCreateActivationRequestWithDNSSuffix(t *testing.T) {

	result, err := p.CreateActivationRequest("method", "vprodemo.com")
	assert.NoError(t, err)
	assert.Equal(t, "method", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.Equal(t, utils.ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, utils.ProjectVersion, result.AppVersion)
}

func TestCreateActivationResponse(t *testing.T) {

	result, err := p.CreateActivationResponse([]byte(""))
	assert.NoError(t, err)
	assert.Equal(t, "response", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.Equal(t, utils.ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, utils.ProjectVersion, result.AppVersion)

}
