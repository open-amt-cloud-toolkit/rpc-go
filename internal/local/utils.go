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

func (service *ProvisioningService) EnumPullUnmarshal(enumFn EnumMessageFunc, pullFn PullMessageFunc, outObj any) int {
	xmlMsg := enumFn()
	log.Trace(xmlMsg)
	xmlRsp, err := service.client.Post(xmlMsg)
	log.Trace(string(xmlRsp))
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

func (service *ProvisioningService) PostAndUnmarshal(xmlMsg string, outObj any) int {
	log.Trace(xmlMsg)
	xmlRsp, err := service.client.Post(xmlMsg)
	log.Trace(string(xmlRsp))
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

func (service *ProvisioningService) GetPublicKeyCerts(certs *[]publickey.PublicKeyCertificate) int {

	var pullRspEnv publickey.PullResponseEnvelope
	resultCode := service.EnumPullUnmarshal(
		service.amtMessages.PublicKeyCertificate.Enumerate,
		service.amtMessages.PublicKeyCertificate.Pull,
		&pullRspEnv,
	)
	if resultCode != utils.Success {
		return resultCode
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
func (service *ProvisioningService) GetPublicPrivateKeyPairs(keyPairs *[]publicprivate.PublicPrivateKeyPair) int {

	var pullRspEnv publicprivate.PullResponseEnvelope
	resultCode := service.EnumPullUnmarshal(
		service.amtMessages.PublicPrivateKeyPair.Enumerate,
		service.amtMessages.PublicPrivateKeyPair.Pull,
		&pullRspEnv,
	)
	if resultCode != utils.Success {
		return resultCode
	}
	for _, keyPair := range pullRspEnv.Body.PullResponse.Items {
		*keyPairs = append(*keyPairs, keyPair)
	}
	return utils.Success
}

func (service *ProvisioningService) DeletePublicPrivateKeyPair(instanceId string) int {
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

func (service *ProvisioningService) DeletePublicCert(instanceId string) int {
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

func (service *ProvisioningService) GetCredentialRelationships() ([]credential.Relationship, int) {
	var items []credential.Relationship
	var pullRspEnv credential.ContextPullResponseEnvelope
	resultCode := service.EnumPullUnmarshal(
		service.cimMessages.CredentialContext.Enumerate,
		service.cimMessages.CredentialContext.Pull,
		&pullRspEnv,
	)
	if resultCode != utils.Success {
		return items, resultCode
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
		resultCode = service.PostAndUnmarshal(
			service.cimMessages.CredentialContext.Pull(enumContext),
			&pullRspEnv,
		)
		if resultCode != utils.Success {
			return items, resultCode
		}
	}
	return items, utils.Success
}

func (service *ProvisioningService) GetConcreteDependencies() ([]concrete.Relationship, int) {
	var items []concrete.Relationship
	var pullRspEnv concrete.DependencyPullResponseEnvelope
	resultCode := service.EnumPullUnmarshal(
		service.cimMessages.ConcreteDependency.Enumerate,
		service.cimMessages.ConcreteDependency.Pull,
		&pullRspEnv,
	)
	if resultCode != utils.Success {
		return items, resultCode
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
		resultCode = service.PostAndUnmarshal(
			service.cimMessages.ConcreteDependency.Pull(enumContext),
			&pullRspEnv,
		)
		if resultCode != utils.Success {
			return items, resultCode
		}
	}
	return items, utils.Success
}
