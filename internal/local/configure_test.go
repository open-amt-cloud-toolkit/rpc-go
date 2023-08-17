package local

import (
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"strings"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim/wifi"

	"github.com/stretchr/testify/assert"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
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

func TestConfigure(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect InvalidParameters for unhandle Subcommand", func(t *testing.T) {
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		resultCode := lps.Configure()
		assert.Equal(t, utils.IncorrectCommandLineParameters, resultCode)
	})
	t.Run("expect MissingWifiConfiguration for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.Configure()
		assert.Equal(t, utils.WSMANMessageError, resultCode)
	})
}

func TestAddWifiSettings(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	pcsRsp := wifiportconfiguration.PortConfigurationResponse{}
	pcsRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
	t.Run("expect Success on happy path", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{})) // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, wifi.PullEnvelope{}))        // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, pcsRsp))
		responsers = append(responsers, respondMsgFunc(t, wifi.RequestStateChangeResponse{}))
		responsers = append(responsers, respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.AddWifiSettings()
		assert.Equal(t, utils.Success, resultCode)
	})
	t.Run("expect error from PruneWifiConfigs path", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.AddWifiSettings()
		assert.NotEqual(t, utils.Success, resultCode)
	})
	t.Run("expect error from EnableWifi path", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{})) // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, wifi.PullEnvelope{}))        // PruneWifiConfigs
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.AddWifiSettings()
		assert.NotEqual(t, utils.Success, resultCode)
	})
}

func TestProcessWifiConfigs(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)
	t.Run("expect WifiConfigurationWithWarnings if some configs fail", func(t *testing.T) {
		f.LocalConfig.WifiConfigs[0].ProfileName = "bad-name"
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessWifiConfigs()
		assert.Equal(t, utils.WifiConfigurationWithWarnings, resultCode)
	})
	t.Run("expect WiFiConfigurationFailed if all configs fail", func(t *testing.T) {
		f.LocalConfig.WifiConfigs[1].ProfileName = "bad-name"
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessWifiConfigs()
		assert.Equal(t, utils.WiFiConfigurationFailed, resultCode)
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
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessWifiConfig(&wifiCfgWPA8021xEAPTLS)
		assert.Equal(t, utils.WSMANMessageError, resultCode)
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = orig
	})
	t.Run("expect WSMANMessageError for AddWiFiSettings()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.Equal(t, utils.WSMANMessageError, resultCode)
	})
	t.Run("expect UnmarshalMessageFailed for AddWiFiSettings()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.Equal(t, utils.UnmarshalMessageFailed, resultCode)
	})
	t.Run("expect unsuccessful return value error for AddWiFiSettings()", func(t *testing.T) {
		msgRsp := wifiportconfiguration.AddWiFiSettingsResponse{}
		msgRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue = 1
		expected := utils.AmtPtStatusCodeBase + msgRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, msgRsp))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.Equal(t, expected, resultCode)
	})
}

func TestPruneWifiConfigs(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect Success when there are no configs", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{}))
		responsers = append(responsers, respondMsgFunc(t, wifi.PullEnvelope{}))
		lps := setupWsmanResponses(t, f, responsers)
		errCode := lps.PruneWifiConfigs()
		assert.Equal(t, utils.Success, errCode)
	})
	t.Run("expect success when there are configs", func(t *testing.T) {
		pullEnvelope := wifi.PullEnvelope{}
		pullEnvelope.Body.PullResponse.Items.WifiSettings = append(pullEnvelope.Body.PullResponse.Items.WifiSettings, wifi.CIMWiFiEndpointSettings{InstanceID: "Config1"})
		pullEnvelope.Body.PullResponse.Items.WifiSettings = append(pullEnvelope.Body.PullResponse.Items.WifiSettings, wifi.CIMWiFiEndpointSettings{InstanceID: "Config2"})

		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{}))
		responsers = append(responsers, respondMsgFunc(t, pullEnvelope))
		responsers = append(responsers, respondMsgFunc(t, "Config1 Deleted"))
		responsers = append(responsers, respondMsgFunc(t, "Config2 Deleted"))
		lps := setupWsmanResponses(t, f, responsers)
		errCode := lps.PruneWifiConfigs()
		assert.Equal(t, utils.Success, errCode)
	})
	t.Run("expect error when enumeration not returned", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, "Not an enumeration envelope"))
		lps := setupWsmanResponses(t, f, responsers)
		errCode := lps.PruneWifiConfigs()
		assert.Equal(t, utils.UnmarshalMessageFailed, errCode)
	})
	t.Run("expect error when pull not returned", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{}))
		responsers = append(responsers, respondMsgFunc(t, "Not a pull envelope"))
		lps := setupWsmanResponses(t, f, responsers)
		errCode := lps.PruneWifiConfigs()
		assert.Equal(t, utils.UnmarshalMessageFailed, errCode)
	})
}

func TestProcessIeee8012xConfig(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect error on missing ieee8021x profile", func(t *testing.T) {
		ieee8021xSettings := &models.IEEE8021xSettings{}
		handles := Handles{}
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		resultCode := lps.ProcessIeee8012xConfig("someothername", ieee8021xSettings, &handles)
		assert.Equal(t, utils.MissingIeee8021xConfiguration, resultCode)
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
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessIeee8012xConfig(ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.WSMANMessageError, resultCode)
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
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, addKeyXMLResponse))
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.WSMANMessageError, resultCode)
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
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, addKeyXMLResponse))
		responsers = append(responsers, respondStringFunc(t, clientCertXMLResponse))
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.WSMANMessageError, resultCode)
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
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, addKeyXMLResponse))
		responsers = append(responsers, respondStringFunc(t, clientCertXMLResponse))
		responsers = append(responsers, respondStringFunc(t, trustedRootXMLResponse))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.Equal(t, utils.Success, resultCode)
		assert.Equal(t, ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings.ElementName)
		assert.NotEmpty(t, handles.privateKeyHandle)
		assert.NotEmpty(t, handles.clientCertHandle)
		assert.NotEmpty(t, handles.rootCertHandle)
	})
}

func TestEnableWifiErrors(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError for WiFiPortConfigurationService.Get()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, resultCode)
	})
	t.Run("expect UnmarshalMessageFailed for WiFiPortConfigurationService.Get()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, utils.UnmarshalMessageFailed, resultCode)
	})
	t.Run("expect WSMANMessageError for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, resultCode)
	})
	t.Run("expect UnmarshalMessageFailed for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, utils.UnmarshalMessageFailed, resultCode)
	})
	t.Run("expect WiFiConfigurationFailed when enable is unsuccessful", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseFailed := wifiportconfiguration.PortConfigurationResponse{}
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseFailed))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, utils.WiFiConfigurationFailed, resultCode)
	})
	t.Run("expect WSMANMessageError for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseEnabled))
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, utils.WSMANMessageError, resultCode)
	})
	t.Run("expect UnmarshalMessageFailed for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseEnabled))
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, utils.UnmarshalMessageFailed, resultCode)
	})
	t.Run("expect non-zero error for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		stateChangeResponse := wifi.RequestStateChangeResponse{}
		stateChangeResponse.Body.RequestStateChange_OUTPUT.ReturnValue = 1
		expected := utils.AmtPtStatusCodeBase + stateChangeResponse.Body.RequestStateChange_OUTPUT.ReturnValue
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseEnabled))
		responsers = append(responsers, respondMsgFunc(t, stateChangeResponse))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.EnableWifi()
		assert.Equal(t, expected, resultCode)
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
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		responsers = append(responsers, respondServerErrFunc())
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		lps.RollbackAddedItems(&handles)
	})
	t.Run("expect all happy paths traversed for coverage", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, "any message works?"))
		responsers = append(responsers, respondStringFunc(t, "any message works?"))
		responsers = append(responsers, respondStringFunc(t, "any message works?"))
		lps := setupWsmanResponses(t, f, responsers)
		lps.RollbackAddedItems(&handles)
	})
}

func TestAddTrustedRootCert(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddTrustedRootCert("AABBCCDD")
		assert.Equal(t, utils.WSMANMessageError, resultCode)
		assert.Empty(t, handle)
	})
	t.Run("expect UnmarshalMessageFailed", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddTrustedRootCert("AABBCCDD")
		assert.Equal(t, utils.UnmarshalMessageFailed, resultCode)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(trustedRootXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		expected := utils.AmtPtStatusCodeBase + 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, dup))
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddTrustedRootCert("AABBCCDD")
		assert.Equal(t, expected, resultCode)
		assert.Empty(t, handle)
	})
}

func TestAddClientCert(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddClientCert("AABBCCDD")
		assert.Equal(t, utils.WSMANMessageError, resultCode)
		assert.Empty(t, handle)
	})
	t.Run("expect UnmarshalMessageFailed", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddClientCert("AABBCCDD")
		assert.Equal(t, utils.UnmarshalMessageFailed, resultCode)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(clientCertXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		expected := utils.AmtPtStatusCodeBase + 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, dup))
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddClientCert("AABBCCDD")
		assert.Equal(t, expected, resultCode)
		assert.Empty(t, handle)
	})
}

func TestAddPrivateKey(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect WSMANMessageError", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddPrivateKey("AABBCCDD")
		assert.Equal(t, utils.WSMANMessageError, resultCode)
		assert.Empty(t, handle)
	})
	t.Run("expect UnmarshalMessageFailed", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddPrivateKey("AABBCCDD")
		assert.Equal(t, utils.UnmarshalMessageFailed, resultCode)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(addKeyXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		expected := utils.AmtPtStatusCodeBase + 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, dup))
		lps := setupWsmanResponses(t, f, responsers)
		handle, resultCode := lps.AddPrivateKey("AABBCCDD")
		assert.Equal(t, expected, resultCode)
		assert.Empty(t, handle)
	})
}

func TestCheckReturnValue(t *testing.T) {
	tests := []struct {
		name string
		in   int
		item string
		want int
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
