/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpc

import (
	"encoding/base64"
	"encoding/json"
	"os"
)

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
type MPSStatusMessage struct {
	Status         string
	Network        string
	CIRAConnection string
}

// ActivationPayload struct is used for the intial request to MPS to activate a device
type ActivationPayload struct {
	Ver         string   `json:"ver"`
	Build       string   `json:"build"`
	Sku         string   `json:"sku"`
	UUID        string   `json:"uuid"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	CurrentMode int      `json:"currentMode"`
	Hostname    string   `json:"hostname"`
	Fqdn        string   `json:"fqdn"`
	Client      string   `json:"client"`
	CertHashes  []string `json:"certHashes"`
}

// createPayload gathers data from ME to assemble required information for sending to the server
func createPayload(dnsSuffix string) (ActivationPayload, error) {
	payload := ActivationPayload{}
	var err error
	payload.Ver, err = GetVersionDataFromME("AMT")
	if err != nil {
		return payload, err
	}
	payload.Build, err = GetVersionDataFromME("Build Number")
	if err != nil {
		return payload, err
	}
	payload.Sku, err = GetVersionDataFromME("Sku")
	if err != nil {
		return payload, err
	}
	payload.UUID, err = GetUUID()
	if err != nil {
		return payload, err
	}
	payload.CurrentMode, err = GetControlMode()
	if err != nil {
		return payload, err
	}
	lsa, err := GetLocalSystemAccount()
	if err != nil {
		return payload, err
	}
	payload.Username = lsa.Username
	payload.Password = lsa.Password

	if dnsSuffix != "" {
		payload.Fqdn = dnsSuffix
	} else {
		payload.Fqdn, err = GetDNSSuffix()
		if err != nil {
			return payload, err
		}
	}

	payload.Hostname, err = os.Hostname()
	if err != nil {
		return payload, err
	}
	payload.Client = ClientName
	hashes, err := GetCertificateHashes()
	if err != nil {
		return payload, err
	}
	for _, v := range hashes {
		payload.CertHashes = append(payload.CertHashes, v.Hash)
	}
	return payload, nil

}

// CreateActivationRequest is used for assembling the message to request activation of a device
func CreateActivationRequest(command string, dnsSuffix string) (Activation, error) {
	activation := Activation{
		Method:          command,
		APIKey:          "key",
		AppVersion:      ProjectVer,
		ProtocolVersion: ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
	}
	payload, err := createPayload(dnsSuffix)
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
func CreateActivationResponse(payload []byte) (Activation, error) {
	activation := Activation{
		Method:          "response",
		APIKey:          "key",
		AppVersion:      ProjectVer,
		ProtocolVersion: ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
		Payload:         base64.StdEncoding.EncodeToString(payload),
	}
	return activation, nil
}
