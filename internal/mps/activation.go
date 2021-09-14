/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package mps

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"rpc/internal/amt"
	"rpc/pkg/utils"
)

type Payload struct {
	AMT amt.AMT
}

// Activation is used for tranferring messages between MPS and RPC
type Activation struct {
	Method          string `json:"method"`
	APIKey          string `json:"apiKey"`
	AppVersion      string `json:"appVersion"`
	ProtocolVersion string `json:"protocolVersion"`
	Status          string `json:"status"`
	Message         string `json:"message"`
	Fqdn            string `json:"fqdn"`
	Payload         string `json:"payload"`
}

// Status Message is used for displaying and parsing status messages from MPS
type StatusMessage struct {
	Status         string
	Network        string
	CIRAConnection string
}

// ActivationPayload struct is used for the initial request to MPS to activate a device
type ActivationPayload struct {
	Version           string   `json:"ver"`
	Build             string   `json:"build"`
	SKU               string   `json:"sku"`
	UUID              string   `json:"uuid"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	CurrentMode       int      `json:"currentMode"`
	Hostname          string   `json:"hostname"`
	FQDN              string   `json:"fqdn"`
	Client            string   `json:"client"`
	CertificateHashes []string `json:"certHashes"`
}

// createPayload gathers data from ME to assemble required information for sending to the server
func (p Payload) createPayload(dnsSuffix string) (ActivationPayload, error) {
	payload := ActivationPayload{}
	var err error
	payload.Version, err = p.AMT.GetVersionDataFromME("AMT")
	if err != nil {
		return payload, err
	}
	payload.Build, err = p.AMT.GetVersionDataFromME("Build Number")
	if err != nil {
		return payload, err
	}
	payload.SKU, err = p.AMT.GetVersionDataFromME("Sku")
	if err != nil {
		return payload, err
	}
	payload.UUID, err = p.AMT.GetUUID()
	if err != nil {
		return payload, err
	}
	payload.CurrentMode, err = p.AMT.GetControlMode()
	if err != nil {
		return payload, err
	}
	lsa, err := p.AMT.GetLocalSystemAccount()
	if err != nil {
		return payload, err
	}
	payload.Username = lsa.Username
	payload.Password = lsa.Password

	if dnsSuffix != "" {
		payload.FQDN = dnsSuffix
	} else {
		payload.FQDN, err = p.AMT.GetDNSSuffix()
		if payload.FQDN == "" {
			payload.FQDN, _ = p.AMT.GetOSDNSSuffix()
		}
		if err != nil {
			return payload, err
		}
	}

	payload.Hostname, err = os.Hostname()
	if err != nil {
		return payload, err
	}
	payload.Client = utils.ClientName
	hashes, err := p.AMT.GetCertificateHashes()
	if err != nil {
		return payload, err
	}
	for _, v := range hashes {
		payload.CertificateHashes = append(payload.CertificateHashes, v.Hash)
	}
	return payload, nil

}

// CreateActivationRequest is used for assembling the message to request activation of a device
func (p Payload) CreateActivationRequest(command string, dnsSuffix string) (Activation, error) {
	activation := Activation{
		Method:          command,
		APIKey:          "key",
		AppVersion:      utils.ProjectVersion,
		ProtocolVersion: utils.ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
	}
	payload, err := p.createPayload(dnsSuffix)
	if err != nil {
		return activation, err
	}
	//convert struct to json
	data, err := json.Marshal(payload)
	if err != nil {
		return activation, err
	}

	activation.Payload = base64.StdEncoding.EncodeToString(data)

	return activation, nil
}

// CreateActivationResponse is used for creating a response to the server
func (p Payload) CreateActivationResponse(payload []byte) (Activation, error) {
	activation := Activation{
		Method:          "response",
		APIKey:          "key",
		AppVersion:      utils.ProjectVersion,
		ProtocolVersion: utils.ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
		Payload:         base64.StdEncoding.EncodeToString(payload),
	}
	return activation, nil
}
