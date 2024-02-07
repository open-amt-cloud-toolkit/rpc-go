package local

import (
	"rpc/internal/certs"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	log "github.com/sirupsen/logrus"
)

const RemoteTLSInstanceId = `Intel(r) AMT 802.3 TLS Settings`
const LocalTLSInstanceId = `Intel(r) AMT LMS TLS Settings`

func (service *ProvisioningService) ConfigureTLS() error {
	log.Info("configuring TLS")
	var handles Handles
	var err error
	defer func() {
		if err != nil {
			service.RollbackAddedItems(&handles)
		}
	}()

	rootComposite, err := certs.NewRootComposite()
	if err != nil {
		return utils.TLSConfigurationFailed
	}
	handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(rootComposite.StripPem())
	if err != nil {
		return err
	}

	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	var keyPairs []publicprivate.PublicPrivateKeyPair
	keyPairs, err = service.interfacedWsmanMessage.GetPublicPrivateKeyPairs()
	if err != nil {
		return err
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

	handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(clientComposite.StripPem())
	if err != nil {
		return err
	}
	log.Debug("TLS rootCertHandle:", handles.rootCertHandle)
	log.Debug("TLS clientCertHandle:", handles.clientCertHandle)
	log.Debug("TLS keyPairHandle:", handles.keyPairHandle)

	err = service.CreateTLSCredentialContext(handles.clientCertHandle)
	if err != nil {
		return err
	}

	err = service.SynchronizeTime()
	if err != nil {
		return err
	}

	err = service.EnableTLS()
	if err != nil {
		log.Error("Failed to configure TLS")
	}
	log.Info("configuring TLS completed successfully")
	return nil
}

func (service *ProvisioningService) GenerateKeyPair() (handle string, err error) {
	log.Info("generating key pair")
	response, err := service.interfacedWsmanMessage.GenerateKeyPair(publickey.RSA, 2048)
	if err != nil {
		return "", err
	}
	if response.Body.GenerateKeyPair_OUTPUT.ReturnValue != 0 {
		log.Errorf("GenerateKeyPair.ReturnValue: %d", response.Body.GenerateKeyPair_OUTPUT.ReturnValue)
		return "", utils.AmtPtStatusCodeBase
	}
	if len(response.Body.GenerateKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selectors) == 0 {
		log.Error("GenerateKeyPair did not return a valid handle")
		return handle, utils.TLSConfigurationFailed
	}
	handle = response.Body.GenerateKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selectors[0].Text
	return handle, nil
}

func (service *ProvisioningService) CreateTLSCredentialContext(certHandle string) error {
	log.Info("creating TLS credential context")
	response, err := service.interfacedWsmanMessage.CreateTLSCredentialContext(certHandle)
	log.Trace(response)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "alreadyexists") {
			log.Info("TLSCredentialContext already exists", certHandle)
		} else {
			log.Error("failed creating TLSCredentialContext", certHandle, err)
			return utils.WSMANMessageError
		}
	}
	return nil
}

func (service *ProvisioningService) EnableTLS() error {
	log.Info("enabling tls")
	enumerateRsp, err := service.interfacedWsmanMessage.EnumerateTLSSettingData()
	if err != nil {
		return utils.WSMANMessageError
	}
	pullRsp, err := service.interfacedWsmanMessage.PullTLSSettingData(enumerateRsp.Body.EnumerateResponse.EnumerationContext)
	for _, item := range pullRsp.Body.PullResponse.SettingDataItems {
		if item.InstanceID == RemoteTLSInstanceId || item.InstanceID == LocalTLSInstanceId {
			err = service.ConfigureTLSSettings(item)
			if err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
	// service.Pause(service.flags.ConfigTLSInfo.DelayInSeconds)
	// time.Sleep(time.Duration(howManySeconds) * time.Second)
	commitResponse, err := service.interfacedWsmanMessage.CommitChanges()
	if err != nil {
		log.Error("commit changes failed")
		return err
	}

	if commitResponse.Body.CommitChanges_OUTPUT.ReturnValue != 0 {
		log.Errorf("CommitChangesResponse non-zero return code: %d", commitResponse.Body.CommitChanges_OUTPUT.ReturnValue)
		return utils.AmtPtStatusCodeBase
	}
	return err
}

func (service *ProvisioningService) ConfigureTLSSettings(setting tls.SettingDataResponse) error {
	data := getTLSSettings(setting, service.flags.ConfigTLSInfo.TLSMode)
	putResponse, err := service.interfacedWsmanMessage.PUTTLSSettings(data.InstanceID, data)
	log.Trace(putResponse)
	if err != nil {
		log.Errorf("failed to configure remote TLS Settings (%s)\n", data.InstanceID)
	}
	return nil
}

func getTLSSettings(setting tls.SettingDataResponse, tlsMode flags.TLSMode) tls.SettingDataRequest {
	data := tls.SettingDataRequest{
		AcceptNonSecureConnections: setting.AcceptNonSecureConnections,
		ElementName:                setting.ElementName,
		Enabled:                    true,
		InstanceID:                 setting.InstanceID,
		MutualAuthentication:       setting.MutualAuthentication,
	}
	if setting.InstanceID == RemoteTLSInstanceId {
		log.Infof("configuring remote TLS settings mode: %s", tlsMode)
		if setting.NonSecureConnectionsSupported {
			data.AcceptNonSecureConnections = tlsMode == flags.TLSModeServerAndNonTLS || tlsMode == flags.TLSModeMutualAndNonTLS
		}
		data.MutualAuthentication = tlsMode == flags.TLSModeMutual || tlsMode == flags.TLSModeMutualAndNonTLS
	} else {
		log.Info("configuring local TLS settings")
	}
	return data
}
