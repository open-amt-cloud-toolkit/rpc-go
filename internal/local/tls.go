package local

import (
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/setupandconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/tls"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	log "github.com/sirupsen/logrus"
	"rpc/internal/certs"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"strings"
)

const RemoteTLSInstanceId = `Intel(r) AMT 802.3 TLS Settings`
const LocalTLSInstanceId = `Intel(r) AMT LMS TLS Settings`

//type TLSContext struct {
//	RootComp   certs.Composite
//	ClientComp certs.Composite
//	Handles    Handles
//}

func (service *ProvisioningService) ConfigureTLS() utils.ReturnCode {
	log.Info("configuring TLS")
	var handles Handles
	var rc utils.ReturnCode
	defer func() {
		if rc != utils.Success {
			service.RollbackAddedItems(&handles)
		}
	}()

	var err error
	rootComposite, err := certs.NewRootComposite()
	if err != nil {
		return utils.TLSConfigurationFailed
	}
	handles.rootCertHandle, rc = service.AddTrustedRootCert(rootComposite.StripPem())
	if rc != utils.Success {
		return rc
	}

	handles.keyPairHandle, rc = service.GenerateKeyPair()
	if rc != utils.Success {
		return rc
	}
	handles.privateKeyHandle = handles.keyPairHandle

	var keyPairs []publicprivate.PublicPrivateKeyPair
	rc = service.GetPublicPrivateKeyPairs(&keyPairs)
	if rc != utils.Success {
		return rc
	}
	var derKey string
	for _, keyPair := range keyPairs {
		if keyPair.InstanceID == handles.keyPairHandle {
			derKey = keyPair.DERKey
			break
		}
	}
	if derKey == "" {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return utils.TLSConfigurationFailed
	}

	clientComposite, err := certs.NewSignedAMTComposite(derKey, &rootComposite)
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	handles.clientCertHandle, rc = service.AddClientCert(clientComposite.StripPem())
	if rc != utils.Success {
		return rc
	}
	log.Debug("TLS rootCertHandle:", handles.rootCertHandle)
	log.Debug("TLS clientCertHandle:", handles.clientCertHandle)
	log.Debug("TLS keyPairHandle:", handles.keyPairHandle)

	rc = service.CreateTLSCredentialContext(handles.clientCertHandle)
	if rc != utils.Success {
		return rc
	}

	rc = service.SynchronizeTime()
	if rc != utils.Success {
		return rc
	}

	rc = service.EnableTLS()
	if rc == utils.Success {
		log.Info("configuring TLS completed successfully")
	}
	return rc
}

func (service *ProvisioningService) GenerateKeyPair() (handle string, rc utils.ReturnCode) {
	log.Info("generating key pair")
	keyPairInput := publickey.GenerateKeyPair_INPUT{
		KeyAlgorithm: publickey.RSA,
		KeyLength:    2048,
	}
	xmlMsg := service.amtMessages.PublicKeyManagementService.GenerateKeyPair(keyPairInput)
	var publicKeyResponse publickey.Response
	rc = service.PostAndUnmarshal(xmlMsg, &publicKeyResponse)
	if rc != utils.Success {
		return handle, rc
	}
	rc = utils.ReturnCode(publicKeyResponse.Body.GeneratedKeyPair_OUTPUT.ReturnValue)
	if rc != 0 {
		log.Errorf("GenerateKeyPair.ReturnValue: %d", rc)
		return handle, utils.AmtPtStatusCodeBase + rc
	}
	if len(publicKeyResponse.Body.GeneratedKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selector) == 0 {
		log.Error("GenerateKeyPair did not return a valid handle")
		return handle, utils.TLSConfigurationFailed
	}
	handle = publicKeyResponse.Body.GeneratedKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selector[0].Value
	return handle, utils.Success
}

func (service *ProvisioningService) CreateTLSCredentialContext(certHandle string) utils.ReturnCode {
	log.Info("creating TLS credential context")
	xmlMsg := service.amtMessages.TLSCredentialContext.Create(certHandle)

	xmlRsp, err := service.client.Post(xmlMsg)
	log.Trace(string(xmlRsp))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "alreadyexists") {
			log.Info("TLSCredentialContext already exists", certHandle)
		} else {
			log.Error("failed creating TLSCredentialContext", certHandle, err)
			return utils.WSMANMessageError
		}
	}
	return utils.Success
}

func (service *ProvisioningService) EnableTLS() utils.ReturnCode {
	log.Info("enabling tls")
	var pullRsp tls.Response
	rc := service.EnumPullUnmarshal(
		service.amtMessages.TLSSettingData.Enumerate,
		service.amtMessages.TLSSettingData.Pull,
		&pullRsp,
	)
	if rc != utils.Success {
		return rc
	}

	for _, item := range pullRsp.Body.PullResponse.TlsSettingItems {
		if item.InstanceID == RemoteTLSInstanceId || item.InstanceID == LocalTLSInstanceId {
			rc = service.ConfigureTLSSettings(&item)
		}
		if rc != utils.Success {
			return rc
		}
	}

	service.Pause(service.flags.ConfigTLSInfo.DelayInSeconds)

	xmlMsg := service.amtMessages.SetupAndConfigurationService.CommitChanges()
	var commitResponse setupandconfiguration.Response
	rc = service.PostAndUnmarshal(xmlMsg, &commitResponse)
	if rc != utils.Success {
		log.Error("commit changes failed")
		return rc
	}
	retVal := commitResponse.Body.CommitChanges_OUTPUT.ReturnValue

	if retVal != common.PT_STATUS_SUCCESS {
		log.Errorf("CommitChangesResponse non-zero return code: %d", retVal)
		return utils.AmtPtStatusCodeBase + utils.ReturnCode(retVal)
	}
	return utils.Success
}

func (service *ProvisioningService) ConfigureTLSSettings(setting *tls.TlsSetting) utils.ReturnCode {
	data := getTLSSettingsPutData(setting, service.flags.ConfigTLSInfo.TLSMode)
	xmlMsg := service.amtMessages.TLSSettingData.Put(data)
	var putResponse tls.Response
	rc := service.PostAndUnmarshal(xmlMsg, &putResponse)
	if rc != utils.Success {
		log.Errorf("failed to configure remote TLS Settings (%s)\n", data.InstanceID)
	}
	return rc
}

func getTLSSettingsPutData(setting *tls.TlsSetting, tlsMode flags.TLSMode) tls.TLSSettingData {
	data := tls.TLSSettingData{
		AcceptNonSecureConnections: setting.AcceptNonSecureConnections,
		ElementName:                setting.ElementName,
		Enabled:                    true,
		InstanceID:                 setting.InstanceID,
		MutualAuthentication:       setting.MutualAuthentication,
	}
	if setting.InstanceID == RemoteTLSInstanceId {
		log.Infof("configuring remote TLS settings mode: %s", tlsMode)
		if setting.NonSecureConnectionsSupported == nil || *setting.NonSecureConnectionsSupported {
			data.AcceptNonSecureConnections = tlsMode == flags.TLSModeServerAndNonTLS || tlsMode == flags.TLSModeMutualAndNonTLS
		}
		data.MutualAuthentication = tlsMode == flags.TLSModeMutual || tlsMode == flags.TLSModeMutualAndNonTLS
	} else {
		log.Info("configuring local TLS settings")
	}
	return data
}
