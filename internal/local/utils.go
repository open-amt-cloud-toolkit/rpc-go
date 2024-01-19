package local

import (
	"encoding/xml"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/concrete"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/credential"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	log "github.com/sirupsen/logrus"
	"reflect"
	"rpc/pkg/utils"
	"strings"
)

func reflectObjectName(v any) string {
	var vName string
	if t := reflect.TypeOf(v); t.Kind() == reflect.Ptr {
		vName = t.Elem().Name()
	} else {
		vName = t.Name()
	}
	return vName
}

type EnumMessageFunc func() string
type PullMessageFunc func(string) string

func (service *ProvisioningService) EnumPullUnmarshal(enumFn EnumMessageFunc, pullFn PullMessageFunc, outObj any) utils.ReturnCode {
	xmlMsg := enumFn()
	xmlRsp, err := service.client.Post(xmlMsg)
	if err != nil {
		log.Errorf("enumerate post call for %s: %s", reflectObjectName(outObj), err)
		return utils.WSMANMessageError
	}
	var enumRsp common.EnumerationResponse
	if err := xml.Unmarshal(xmlRsp, &enumRsp); err != nil {
		log.Errorf("enumerate unmarshal call for %s: %s", reflectObjectName(outObj), err)
		return utils.UnmarshalMessageFailed
	}
	xmlMsg = pullFn(enumRsp.Body.EnumerateResponse.EnumerationContext)
	return service.PostAndUnmarshal(xmlMsg, outObj)
}

func (service *ProvisioningService) PostAndUnmarshal(xmlMsg string, outObj any) utils.ReturnCode {
	xmlRsp, err := service.client.Post(xmlMsg)
	if err != nil {
		log.Errorf("post call for %s: %s", reflectObjectName(outObj), err)
		return utils.WSMANMessageError
	}
	if err := xml.Unmarshal(xmlRsp, outObj); err != nil {
		log.Errorf("unmarshal call for %s: %s", reflectObjectName(outObj), err)
		return utils.UnmarshalMessageFailed
	}
	return utils.Success
}

func GetTokenFromKeyValuePairs(kvList string, token string) string {
	attributes := strings.Split(kvList, ",")
	tokenMap := make(map[string]string)
	for _, att := range attributes {
		parts := strings.Split(att, "=")
		tokenMap[parts[0]] = parts[1]
	}
	return tokenMap[token]
}

func (service *ProvisioningService) GetPublicKeyCerts(certs *[]publickey.PublicKeyCertificate) utils.ReturnCode {

	var pullRspEnv publickey.PullResponseEnvelope
	rc := service.EnumPullUnmarshal(
		service.amtMessages.PublicKeyCertificate.Enumerate,
		service.amtMessages.PublicKeyCertificate.Pull,
		&pullRspEnv,
	)
	if rc != utils.Success {
		return rc
	}
	for _, publicKeyCert := range pullRspEnv.Body.PullResponse.Items {
		*certs = append(*certs, publicKeyCert)
	}
	return utils.Success
}

// GetPublicPrivateKeyPairs
// NOTE: RSA Key encoded as DES PKCS#1. The Exponent (E) is 65537 (0x010001).
// When this structure is used as an output parameter (GET or PULL method),
// only the public section of the key is exported.
func (service *ProvisioningService) GetPublicPrivateKeyPairs(keyPairs *[]publicprivate.PublicPrivateKeyPair) utils.ReturnCode {

	var pullRspEnv publicprivate.PullResponseEnvelope
	rc := service.EnumPullUnmarshal(
		service.amtMessages.PublicPrivateKeyPair.Enumerate,
		service.amtMessages.PublicPrivateKeyPair.Pull,
		&pullRspEnv,
	)
	if rc != utils.Success {
		return rc
	}
	for _, keyPair := range pullRspEnv.Body.PullResponse.Items {
		*keyPairs = append(*keyPairs, keyPair)
	}
	return utils.Success
}

func (service *ProvisioningService) DeletePublicPrivateKeyPair(instanceId string) utils.ReturnCode {
	log.Infof("deleting public private key pair instance: %s", instanceId)
	xmlMsg := service.amtMessages.PublicPrivateKeyPair.Delete(instanceId)
	// the response has no addiitonal information
	// if post is successful, then deletion is successful
	_, err := service.client.Post(xmlMsg)
	if err != nil {
		log.Errorf("unable to delete: %s", instanceId)
		return utils.DeleteWifiConfigFailed
	}
	return utils.Success
}

func (service *ProvisioningService) DeletePublicCert(instanceId string) utils.ReturnCode {
	log.Infof("deleting public key certificate instance: %s", instanceId)
	xmlMsg := service.amtMessages.PublicKeyCertificate.Delete(instanceId)
	// the response has no addiitonal information
	// if post is successful, then deletion is successful
	_, err := service.client.Post(xmlMsg)
	if err != nil {
		log.Errorf("unable to delete: %s", instanceId)
		return utils.DeleteWifiConfigFailed
	}
	return utils.Success
}

func (service *ProvisioningService) GetCredentialRelationships() ([]credential.Relationship, utils.ReturnCode) {
	var items []credential.Relationship
	var pullRspEnv credential.ContextPullResponseEnvelope
	rc := service.EnumPullUnmarshal(
		service.cimMessages.CredentialContext.Enumerate,
		service.cimMessages.CredentialContext.Pull,
		&pullRspEnv,
	)
	if rc != utils.Success {
		return items, rc
	}
	for {
		for i := range pullRspEnv.Body.PullResponse.Items {
			items = append(items, pullRspEnv.Body.PullResponse.Items[i])
		}
		enumContext := pullRspEnv.Body.PullResponse.EnumerationContext
		if enumContext == "" {
			break
		}
		pullRspEnv = credential.ContextPullResponseEnvelope{}
		rc = service.PostAndUnmarshal(
			service.cimMessages.CredentialContext.Pull(enumContext),
			&pullRspEnv,
		)
		if rc != utils.Success {
			return items, rc
		}
	}
	return items, utils.Success
}

func (service *ProvisioningService) GetConcreteDependencies() ([]concrete.Relationship, utils.ReturnCode) {
	var items []concrete.Relationship
	var pullRspEnv concrete.DependencyPullResponseEnvelope
	rc := service.EnumPullUnmarshal(
		service.cimMessages.ConcreteDependency.Enumerate,
		service.cimMessages.ConcreteDependency.Pull,
		&pullRspEnv,
	)
	if rc != utils.Success {
		return items, rc
	}
	for {
		for i := range pullRspEnv.Body.PullResponse.Items {
			items = append(items, pullRspEnv.Body.PullResponse.Items[i])
		}
		enumContext := pullRspEnv.Body.PullResponse.EnumerationContext
		if enumContext == "" {
			break
		}
		pullRspEnv = concrete.DependencyPullResponseEnvelope{}
		rc = service.PostAndUnmarshal(
			service.cimMessages.ConcreteDependency.Pull(enumContext),
			&pullRspEnv,
		)
		if rc != utils.Success {
			return items, rc
		}
	}
	return items, utils.Success
}
