package local

import (
	"reflect"
	"rpc/pkg/utils"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman/cim/concrete"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman/cim/credential"
	log "github.com/sirupsen/logrus"
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

func GetTokenFromKeyValuePairs(kvList string, token string) string {
	attributes := strings.Split(kvList, ",")
	tokenMap := make(map[string]string)
	for _, att := range attributes {
		parts := strings.Split(att, "=")
		tokenMap[parts[0]] = parts[1]
	}
	return tokenMap[token]
}

func (service *ProvisioningService) GetPublicKeyCerts() ([]publickey.PublicKeyCertificateResponse, error) {

	response, err := service.wsmanMessages.AMT.PublicKeyCertificate.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = service.wsmanMessages.AMT.PublicKeyCertificate.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return response.Body.PullResponse.PublicKeyCertificateItems, nil
}

// GetPublicPrivateKeyPairs
// NOTE: RSA Key encoded as DES PKCS#1. The Exponent (E) is 65537 (0x010001).
// When this structure is used as an output parameter (GET or PULL method),
// only the public section of the key is exported.
func (service *ProvisioningService) GetPublicPrivateKeyPairs(keyPairs *[]publicprivate.PublicPrivateKeyPair) ([]publicprivate.PublicPrivateKeyPair, error) {
	response, err := service.wsmanMessages.AMT.PublicPrivateKeyPair.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = service.wsmanMessages.AMT.PublicPrivateKeyPair.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.PublicPrivateKeyPairItems, nil
}

func (service *ProvisioningService) DeletePublicPrivateKeyPair(instanceId string) error {
	log.Infof("deleting public private key pair instance: %s", instanceId)
	_, err := service.wsmanMessages.AMT.PublicPrivateKeyPair.Delete(instanceId)
	if err != nil {
		log.Errorf("unable to delete: %s", instanceId)
		return utils.DeleteWifiConfigFailed
	}
	return nil
}

func (service *ProvisioningService) DeletePublicCert(instanceId string) error {
	log.Infof("deleting public key certificate instance: %s", instanceId)
	_, err := service.wsmanMessages.AMT.PublicKeyCertificate.Delete(instanceId)
	if err != nil {
		log.Errorf("unable to delete: %s", instanceId)
		return utils.DeleteWifiConfigFailed
	}
	return nil
}

func (service *ProvisioningService) GetCredentialRelationships() ([]credential.CredentialContext, error) {
	response, err := service.wsmanMessages.CIM.CredentialContext.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = service.wsmanMessages.CIM.CredentialContext.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.Items, nil
}

func (service *ProvisioningService) GetConcreteDependencies() ([]concrete.ConcreteDependency, error) {
	response, err := service.wsmanMessages.CIM.ConcreteDependency.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = service.wsmanMessages.CIM.ConcreteDependency.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.Items, nil
}
