package local

import (
	"regexp"
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"strings"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/credential"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/wifi"

	"github.com/stretchr/testify/assert"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"
)

const trustedRootXMLResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:e=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:f=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><a:Header><b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To><b:RelatesTo>2</b:RelatesTo><b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps/AddTrustedRootCertificateResponse</b:Action><b:MessageID>uuid:00000000-8086-8086-8086-00000003A988</b:MessageID><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps</c:ResourceURI></a:Header><a:Body><g:AddTrustedRootCertificate_OUTPUT><g:CreatedCertificate><b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address><b:ReferenceParameters><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI><c:SelectorSet><c:Selector Name=\"InstanceID\">Intel(r) AMT Certificate: Handle: 2</c:Selector></c:SelectorSet></b:ReferenceParameters></g:CreatedCertificate><g:ReturnValue>0</g:ReturnValue></g:AddTrustedRootCertificate_OUTPUT></a:Body></a:Envelope>"
const clientCertXMLResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:e=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:f=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><a:Header><b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To><b:RelatesTo>1</b:RelatesTo><b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps/AddCertificateResponse</b:Action><b:MessageID>uuid:00000000-8086-8086-8086-00000003A89C</b:MessageID><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps</c:ResourceURI></a:Header><a:Body><g:AddCertificate_OUTPUT><g:CreatedCertificate><b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address><b:ReferenceParameters><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI><c:SelectorSet><c:Selector Name=\"InstanceID\">Intel(r) AMT Certificate: Handle: 1</c:Selector></c:SelectorSet></b:ReferenceParameters></g:CreatedCertificate><g:ReturnValue>0</g:ReturnValue></g:AddCertificate_OUTPUT></a:Body></a:Envelope>"
const addKeyXMLResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:e=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:f=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><a:Header><b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To><b:RelatesTo>0</b:RelatesTo><b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps/AddKeyResponse</b:Action><b:MessageID>uuid:00000000-8086-8086-8086-00000003A89B</b:MessageID><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps</c:ResourceURI></a:Header><a:Body><g:AddKey_OUTPUT><g:CreatedKey><b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address><b:ReferenceParameters><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair</c:ResourceURI><c:SelectorSet><c:Selector Name=\"InstanceID\">Intel(r) AMT Key: Handle: 0</c:Selector></c:SelectorSet></b:ReferenceParameters></g:CreatedKey><g:ReturnValue>0</g:ReturnValue></g:AddKey_OUTPUT></a:Body></a:Envelope>"

var wifiCfgWPA = config.WifiConfig{
	ProfileName:          "wifiWPA",
	SSID:                 "ssid",
	Priority:             1,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA_PSK),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPAPassPhrase",
	Ieee8021xProfileName: "",
}

var wifiCfgWPA2 = config.WifiConfig{
	ProfileName:          "wifiWPA2",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA2_PSK),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPAPassPhrase",
	Ieee8021xProfileName: "",
}

var wifiCfgWPA8021xEAPTLS = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA_IEEE8021x),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	PskPassphrase:        "",
	Ieee8021xProfileName: "ieee8021xCfgEAPTLS",
}

var ieee8021xCfgEAPTLS = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgEAPTLS",
	Username:               "username",
	Password:               "",
	AuthenticationProtocol: int(models.AuthenticationProtocolEAPTLS),
	ClientCert:             "clientCert",
	CACert:                 "caCert",
	PrivateKey:             "privateKey",
}

var wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2 = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(models.AuthenticationMethod_WPA2_IEEE8021x),
	EncryptionMethod:     int(models.EncryptionMethod_CCMP),
	PskPassphrase:        "",
	Ieee8021xProfileName: "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
}

var ieee8021xCfgPEAPv0_EAPMSCHAPv2 = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
	Username:               "username",
	Password:               "password",
	AuthenticationProtocol: int(models.AuthenticationProtocolPEAPv0_EAPMSCHAPv2),
	ClientCert:             "clientCert",
	CACert:                 "caCert",
	PrivateKey:             "privateKey",
}

func emptyPublicPrivateCertsResponsers(t *testing.T) ResponseFuncArray {
	return ResponseFuncArray{
		respondMsgFunc(t, common.EnumerationResponse{}),
		respondMsgFunc(t, publickey.PullResponseEnvelope{}),
		respondMsgFunc(t, common.EnumerationResponse{}),
		respondMsgFunc(t, publicprivate.PullResponseEnvelope{}),
	}
}

func emptyGetWifiIeee8021xCerts(t *testing.T) ResponseFuncArray {
	return append(
		emptyPublicPrivateCertsResponsers(t),
		ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondMsgFunc(t, credential.ContextPullResponseEnvelope{}),
		}...,
	)
}

func TestConfigure(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect error for unhandled Subcommand", func(t *testing.T) {
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		rc := lps.Configure()
		assert.Equal(t, utils.IncorrectCommandLineParameters, rc)
	})
	t.Run("expect error for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.Configure()
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
	t.Run("expect error for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.Configure()
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
}

func TestAddWifiSettings(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	pcsRsp := wifiportconfiguration.Response{}
	pcsRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
	t.Run("expect Success on happy path", func(t *testing.T) {
		rfa := append(
			emptyGetWifiIeee8021xCerts(t),
			ResponseFuncArray{
				respondMsgFunc(t, common.EnumerationResponse{}),
				respondMsgFunc(t, wifi.PullResponseEnvelope{}),
				respondMsgFunc(t, pcsRsp),
				respondMsgFunc(t, wifi.RequestStateChangeResponse{}),
				respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}),
			}...,
		)
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.AddWifiSettings()
		assert.Equal(t, utils.Success, rc)
	})
	t.Run("expect error from PruneWifiConfigs path", func(t *testing.T) {
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.AddWifiSettings()
		assert.NotEqual(t, utils.Success, rc)
	})
	t.Run("expect error from EnableWifi path", func(t *testing.T) {
		rfa := ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondMsgFunc(t, wifi.PullResponseEnvelope{}),
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.AddWifiSettings()
		assert.NotEqual(t, utils.Success, rc)
	})
}

func TestProcessWifiConfigs(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)
	t.Run("expect WifiConfigurationWithWarnings if some configs fail", func(t *testing.T) {
		f.LocalConfig.WifiConfigs[0].ProfileName = "bad-name"
		rfa := ResponseFuncArray{
			respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessWifiConfigs()
		assert.Equal(t, utils.WifiConfigurationWithWarnings, rc)
	})
	t.Run("expect WiFiConfigurationFailed if all configs fail", func(t *testing.T) {
		f.LocalConfig.WifiConfigs[1].ProfileName = "bad-name"
		rfa := ResponseFuncArray{
			respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessWifiConfigs()
		assert.Equal(t, utils.WiFiConfigurationFailed, rc)
	})
}

func TestProcessWifiConfig(t *testing.T) {
	f := &flags.Flags{}

	// bad name error already tested
	t.Run("expect WSMANMessageError for ProcessIeee8012xConfig", func(t *testing.T) {
		orig := wifiCfgWPA8021xEAPTLS.AuthenticationMethod
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = int(models.AuthenticationMethod_WPA_IEEE8021x)
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessWifiConfig(&wifiCfgWPA8021xEAPTLS)
		assert.Equal(t, utils.WSMANMessageError, rc)
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = orig
	})
	t.Run("expect WSMANMessageError for AddWiFiSettings()", func(t *testing.T) {
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
	t.Run("expect UnmarshalMessageFailed for AddWiFiSettings()", func(t *testing.T) {
		rfa := ResponseFuncArray{respondBadXmlFunc(t)}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.Equal(t, utils.UnmarshalMessageFailed, rc)
	})
	t.Run("expect unsuccessful return value error for AddWiFiSettings()", func(t *testing.T) {
		msgRsp := wifiportconfiguration.AddWiFiSettingsResponse{}
		msgRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue = 1
		expected := utils.AmtPtStatusCodeBase + utils.ReturnCode(msgRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue)
		rfa := ResponseFuncArray{respondMsgFunc(t, msgRsp)}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.Equal(t, expected, rc)
	})
}

func TestPruneWifiConfigs(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect Success when there are no configs", func(t *testing.T) {
		rfa := append(
			emptyGetWifiIeee8021xCerts(t),
			ResponseFuncArray{
				respondMsgFunc(t, common.EnumerationResponse{}),
				respondMsgFunc(t, wifi.PullResponseEnvelope{}),
			}...,
		)
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.PruneWifiConfigs()
		assert.Equal(t, utils.Success, rc)
	})
	t.Run("expect success when there are configs", func(t *testing.T) {
		pullEnvelope := wifi.PullResponseEnvelope{}
		pullEnvelope.Body.PullResponse.Items = append(pullEnvelope.Body.PullResponse.Items, wifi.CIMWiFiEndpointSettings{InstanceID: "Config1"})
		pullEnvelope.Body.PullResponse.Items = append(pullEnvelope.Body.PullResponse.Items, wifi.CIMWiFiEndpointSettings{InstanceID: "Config2"})
		pullEnvelope.Body.PullResponse.Items = append(pullEnvelope.Body.PullResponse.Items, wifi.CIMWiFiEndpointSettings{InstanceID: ""})
		rfa := append(
			emptyGetWifiIeee8021xCerts(t),
			ResponseFuncArray{
				respondMsgFunc(t, common.EnumerationResponse{}),
				respondMsgFunc(t, pullEnvelope),
				respondMsgFunc(t, "Config1 Deleted"),
				respondMsgFunc(t, "Config2 Deleted"),
				respondServerErrFunc(), // this one should NOT get called
			}...,
		)
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.PruneWifiConfigs()
		assert.Equal(t, utils.Success, rc)
	})
	t.Run("expect DeleteWifiConfigFailed", func(t *testing.T) {
		pullEnvelope := wifi.PullResponseEnvelope{}
		pullEnvelope.Body.PullResponse.Items = append(pullEnvelope.Body.PullResponse.Items, wifi.CIMWiFiEndpointSettings{InstanceID: "Config1"})
		pullEnvelope.Body.PullResponse.Items = append(pullEnvelope.Body.PullResponse.Items, wifi.CIMWiFiEndpointSettings{InstanceID: "Config2"})
		rfa := append(
			emptyGetWifiIeee8021xCerts(t),
			ResponseFuncArray{
				respondMsgFunc(t, common.EnumerationResponse{}),
				respondMsgFunc(t, pullEnvelope),
				respondMsgFunc(t, "Config1 Deleted"),
				respondServerErrFunc(),
			}...,
		)
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.PruneWifiConfigs()
		assert.Equal(t, utils.DeleteWifiConfigFailed, rc)
	})
	t.Run("expect WSMANMessageError error on EnumPullUnmarshal", func(t *testing.T) {
		rfa := append(
			emptyGetWifiIeee8021xCerts(t),
			ResponseFuncArray{
				respondServerErrFunc(),
			}...,
		)
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.PruneWifiConfigs()
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
}

func TestPruneIeee8012xConfig(t *testing.T) {
	f := &flags.Flags{}
	certHandles := []string{"handle 1", "handle 2"}
	keyPairHandles := []string{"handle 3", "handle 4"}
	rfa := ResponseFuncArray{
		respondMsgFunc(t, "Deleted"),
		respondServerErrFunc(),
		respondMsgFunc(t, "Deleted"),
		respondServerErrFunc(),
	}
	lps := setupWsmanResponses(t, f, rfa)
	failCerts, failKeyPairs := lps.PruneWifiIeee8021xCerts(certHandles, keyPairHandles)
	assert.NotEmpty(t, failCerts)
	assert.Equal(t, "handle 2", failCerts[0])
	assert.NotEmpty(t, failKeyPairs)
	assert.Equal(t, "handle 4", failKeyPairs[0])
}

func TestGetWifiIeee8021xCerts(t *testing.T) {
	f := &flags.Flags{}
	re := regexp.MustCompile(enumCtxElement)
	relationshipsEOS := re.ReplaceAllString(credCtxPullRspString, endOfSequenceElement)
	dependenciesEOS := re.ReplaceAllString(concreteDependencyPullRspString, endOfSequenceElement)
	// make a puclickey response to match the credCtx
	instanceId := "Intel(r) AMT Certificate: Handle: 1"
	x509CertString := "ThisIsJustFakeCertBytes"
	pkPullRspEnv := publickey.PullResponseEnvelope{}
	pkPullRspEnv.Body.PullResponse.Items = []publickey.PublicKeyCertificate{
		{
			InstanceID:      instanceId,
			X509Certificate: x509CertString,
		},
	}
	rfa := ResponseFuncArray{
		respondMsgFunc(t, common.EnumerationResponse{}),
		respondMsgFunc(t, pkPullRspEnv),
		respondMsgFunc(t, common.EnumerationResponse{}),
		respondMsgFunc(t, publicprivate.PullResponseEnvelope{}),
		respondMsgFunc(t, common.EnumerationResponse{}),
		respondStringFunc(t, relationshipsEOS),
		respondMsgFunc(t, common.EnumerationResponse{}),
		respondStringFunc(t, dependenciesEOS),
	}
	lps := setupWsmanResponses(t, f, rfa)
	certHandles, keyPairHandles := lps.GetWifiIeee8021xCerts()
	assert.Equal(t, 2, len(certHandles))
	assert.Equal(t, 1, len(keyPairHandles))
	assert.Equal(t, x509CertString, lps.handlesWithCerts[instanceId])
}

func TestProcessIeee8012xConfig(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect error on missing ieee8021x profile", func(t *testing.T) {
		ieee8021xSettings := &models.IEEE8021xSettings{}
		handles := Handles{}
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		rc := lps.ProcessIeee8012xConfig("someothername", ieee8021xSettings, &handles)
		assert.Equal(t, utils.MissingIeee8021xConfiguration, rc)
		assert.Empty(t, ieee8021xSettings.ElementName)
		assert.Empty(t, handles.privateKeyHandle)
		assert.Empty(t, handles.clientCertHandle)
		assert.Empty(t, handles.rootCertHandle)
	})
	t.Run("expect error on AddPrivateKey error", func(t *testing.T) {
		ieee8021xSettings := &models.IEEE8021xSettings{}
		handles := Handles{}
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgPEAPv0_EAPMSCHAPv2)
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessIeee8012xConfig(ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Equal(t, ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName, ieee8021xSettings.ElementName)
		assert.Empty(t, handles.privateKeyHandle)
		assert.Empty(t, handles.clientCertHandle)
		assert.Empty(t, handles.rootCertHandle)
	})
	t.Run("expect error on AddClientCert error", func(t *testing.T) {
		ieee8021xSettings := &models.IEEE8021xSettings{}
		handles := Handles{}
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		rfa := ResponseFuncArray{
			respondStringFunc(t, addKeyXMLResponse),
			respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Equal(t, ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings.ElementName)
		assert.NotEmpty(t, handles.privateKeyHandle)
		assert.Empty(t, handles.clientCertHandle)
		assert.Empty(t, handles.rootCertHandle)
	})
	t.Run("expect error on AddTrustedRootCert error", func(t *testing.T) {
		ieee8021xSettings := &models.IEEE8021xSettings{}
		handles := Handles{}
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		rfa := ResponseFuncArray{
			respondStringFunc(t, addKeyXMLResponse),
			respondStringFunc(t, clientCertXMLResponse),
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Equal(t, ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings.ElementName)
		assert.NotEmpty(t, handles.privateKeyHandle)
		assert.NotEmpty(t, handles.clientCertHandle)
		assert.Empty(t, handles.rootCertHandle)
	})
	t.Run("expect success on happy path", func(t *testing.T) {
		ieee8021xSettings := &models.IEEE8021xSettings{}
		handles := Handles{}
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		rfa := ResponseFuncArray{
			respondStringFunc(t, addKeyXMLResponse),
			respondStringFunc(t, clientCertXMLResponse),
			respondStringFunc(t, trustedRootXMLResponse),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.Success, rc)
		assert.Equal(t, ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings.ElementName)
		assert.NotEmpty(t, handles.privateKeyHandle)
		assert.NotEmpty(t, handles.clientCertHandle)
		assert.NotEmpty(t, handles.rootCertHandle)
	})
}

func TestEnableWifiErrors(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError for WiFiPortConfigurationService.Get()", func(t *testing.T) {
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
	t.Run("expect UnmarshalMessageFailed for WiFiPortConfigurationService.Get()", func(t *testing.T) {
		rfa := ResponseFuncArray{respondBadXmlFunc(t)}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, utils.UnmarshalMessageFailed, rc)
	})
	t.Run("expect WSMANMessageError for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.Response{}
		rfa := ResponseFuncArray{
			respondMsgFunc(t, pcsResponse),
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
	t.Run("expect UnmarshalMessageFailed for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.Response{}
		rfa := ResponseFuncArray{
			respondMsgFunc(t, pcsResponse),
			respondBadXmlFunc(t),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, utils.UnmarshalMessageFailed, rc)
	})
	t.Run("expect WiFiConfigurationFailed when enable is unsuccessful", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.Response{}
		pcsResponseFailed := wifiportconfiguration.Response{}
		rfa := ResponseFuncArray{
			respondMsgFunc(t, pcsResponse),
			respondMsgFunc(t, pcsResponseFailed),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, utils.WiFiConfigurationFailed, rc)
	})
	t.Run("expect WSMANMessageError for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.Response{}
		pcsResponseEnabled := wifiportconfiguration.Response{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		rfa := ResponseFuncArray{
			respondMsgFunc(t, pcsResponse),
			respondMsgFunc(t, pcsResponseEnabled),
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
	t.Run("expect UnmarshalMessageFailed for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.Response{}
		pcsResponseEnabled := wifiportconfiguration.Response{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		rfa := ResponseFuncArray{
			respondMsgFunc(t, pcsResponse),
			respondMsgFunc(t, pcsResponseEnabled),
			respondBadXmlFunc(t),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, utils.UnmarshalMessageFailed, rc)
	})
	t.Run("expect non-zero error for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.Response{}
		pcsResponseEnabled := wifiportconfiguration.Response{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		stateChangeResponse := wifi.RequestStateChangeResponse{}
		stateChangeResponse.Body.RequestStateChange_OUTPUT.ReturnValue = 1
		expected := utils.AmtPtStatusCodeBase + utils.ReturnCode(stateChangeResponse.Body.RequestStateChange_OUTPUT.ReturnValue)
		rfa := ResponseFuncArray{
			respondMsgFunc(t, pcsResponse),
			respondMsgFunc(t, pcsResponseEnabled),
			respondMsgFunc(t, stateChangeResponse),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifi()
		assert.Equal(t, expected, rc)
	})
}

func TestRollbackAddedItems(t *testing.T) {
	f := &flags.Flags{}
	handles := Handles{
		privateKeyHandle: "privateKeyHandle",
		clientCertHandle: "clientCertHandle",
		rootCertHandle:   "rootCertHandle",
	}

	t.Run("expect all error paths traversed for coverage", func(t *testing.T) {
		rfa := ResponseFuncArray{
			respondServerErrFunc(),
			respondServerErrFunc(),
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, rfa)
		lps.RollbackAddedItems(&handles)
	})
	t.Run("expect all happy paths traversed for coverage", func(t *testing.T) {
		rfa := ResponseFuncArray{
			respondStringFunc(t, "any message works?"),
			respondStringFunc(t, "any message works?"),
			respondStringFunc(t, "any message works?"),
		}
		lps := setupWsmanResponses(t, f, rfa)
		lps.RollbackAddedItems(&handles)
	})
}

func TestAddTrustedRootCert(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError", func(t *testing.T) {
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddTrustedRootCert("AABBCCDD")
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect UnmarshalMessageFailed", func(t *testing.T) {
		rfa := ResponseFuncArray{respondBadXmlFunc(t)}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddTrustedRootCert("AABBCCDD")
		assert.Equal(t, utils.UnmarshalMessageFailed, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(trustedRootXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		expected := utils.AmtPtStatusCodeBase + 1
		rfa := ResponseFuncArray{respondStringFunc(t, dup)}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddTrustedRootCert("AABBCCDD")
		assert.Equal(t, expected, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect success when credential already added", func(t *testing.T) {
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		instanceId := `Intel® AMT XXXCertYYYkey: Handle: 1`
		associatedCredential := `THISISAFAKECERTSTRING`
		lps.handlesWithCerts[instanceId] = associatedCredential
		handle, resultCode := lps.AddTrustedRootCert(associatedCredential)
		assert.Equal(t, utils.Success, resultCode)
		assert.Equal(t, instanceId, handle)
	})
}

func TestAddClientCert(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError", func(t *testing.T) {
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddClientCert("AABBCCDD")
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect UnmarshalMessageFailed", func(t *testing.T) {
		rfa := ResponseFuncArray{respondBadXmlFunc(t)}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddClientCert("AABBCCDD")
		assert.Equal(t, utils.UnmarshalMessageFailed, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(clientCertXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		expected := utils.AmtPtStatusCodeBase + 1
		rfa := ResponseFuncArray{respondStringFunc(t, dup)}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddClientCert("AABBCCDD")
		assert.Equal(t, expected, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect success when credential already added", func(t *testing.T) {
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		instanceId := `Intel® AMT XXXCertYYYkey: Handle: 1`
		associatedCredential := `THISISAFAKECERTSTRING`
		lps.handlesWithCerts[instanceId] = associatedCredential
		handle, resultCode := lps.AddClientCert(associatedCredential)
		assert.Equal(t, utils.Success, resultCode)
		assert.Equal(t, instanceId, handle)
	})
}

func TestAddPrivateKey(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError", func(t *testing.T) {
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddPrivateKey("AABBCCDD")
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect UnmarshalMessageFailed", func(t *testing.T) {
		rfa := ResponseFuncArray{respondBadXmlFunc(t)}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddPrivateKey("AABBCCDD")
		assert.Equal(t, utils.UnmarshalMessageFailed, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(addKeyXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		expected := utils.AmtPtStatusCodeBase + 1
		rfa := ResponseFuncArray{respondStringFunc(t, dup)}
		lps := setupWsmanResponses(t, f, rfa)
		handle, rc := lps.AddPrivateKey("AABBCCDD")
		assert.Equal(t, expected, rc)
		assert.Empty(t, handle)
	})
	t.Run("expect success when credential already added", func(t *testing.T) {
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		instanceId := `Intel® AMT XXXCertYYYkey: Handle: 1`
		associatedCredential := `THISISAFAKECERTSTRING`
		lps.handlesWithCerts[instanceId] = associatedCredential
		handle, resultCode := lps.AddPrivateKey(associatedCredential)
		assert.Equal(t, utils.Success, resultCode)
		assert.Equal(t, instanceId, handle)
	})
}

func TestCheckReturnValue(t *testing.T) {
	tests := []struct {
		name string
		in   utils.ReturnCode
		item string
		want utils.ReturnCode
	}{
		{"TestNoError", 0, "item", utils.Success},
		{"TestAlreadyExists", common.PT_STATUS_DUPLICATE, "item", utils.AmtPtStatusCodeBase + common.PT_STATUS_DUPLICATE},
		{"TestInvalidItem", common.PT_STATUS_INVALID_CERT, "item", utils.AmtPtStatusCodeBase + common.PT_STATUS_INVALID_CERT},
		{"TestNonZeroReturnCode", 2082, "item", utils.AmtPtStatusCodeBase + 2082},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkReturnValue(tt.in, tt.item)
			assert.Equal(t, tt.want, got)
		})
	}
}
func TestEnableWifiPort(t *testing.T) {
	f := &flags.Flags{}
	pcsRsp := wifiportconfiguration.Response{}
	pcsRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
	pcsRsp.Body.WiFiPortConfigurationService.EnabledState = 1
	t.Run("enablewifiport: expect Success on happy path", func(t *testing.T) {
		rfa := ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondMsgFunc(t, wifi.PullResponseEnvelope{}),
			respondMsgFunc(t, pcsRsp),
			respondMsgFunc(t, wifi.RequestStateChangeResponse{}),
		}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifiPort()
		assert.Equal(t, utils.Success, rc)
	})
	t.Run("enablewifiport: expect WSMANMessageError ", func(t *testing.T) {
		rfa := ResponseFuncArray{respondServerErrFunc()}
		lps := setupWsmanResponses(t, f, rfa)
		rc := lps.EnableWifiPort()
		assert.Equal(t, utils.WSMANMessageError, rc)
	})
}
