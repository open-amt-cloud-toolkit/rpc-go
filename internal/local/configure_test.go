package local

import (
	"encoding/xml"
	"fmt"
	"net/http"
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
const addWifiSettingsResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:e=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:f=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><a:Header><b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To><b:RelatesTo>0</b:RelatesTo><b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps/AddKeyResponse</b:Action><b:MessageID>uuid:00000000-8086-8086-8086-00000003A89B</b:MessageID><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementlps</c:ResourceURI></a:Header><a:Body><g:AddWiFiSettings_OUTPUT><g:CreatedKey><b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address><b:ReferenceParameters><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair</c:ResourceURI><c:SelectorSet><c:Selector Name=\"InstanceID\">Intel(r) AMT Key: Handle: 0</c:Selector></c:SelectorSet></b:ReferenceParameters></g:CreatedKey><g:ReturnValue>a</g:ReturnValue></g:AddWiFiSettings_OUTPUT></a:Body></a:Envelope>"

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

// TODO: remove these when local-acm-activation branch is available in main
type ResponseFuncArray []func(w http.ResponseWriter, r *http.Request)

func setupWsmanResponses(t *testing.T, f *flags.Flags, responses ResponseFuncArray) ProvisioningService {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		responses[0](w, r)
		responses = responses[1:]
	})
	return setupWithWsmanClient(f, handler)
}

func respondServerErrFunc() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func respondBadXmlFunc(t *testing.T) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`not really xml is it?`))
		assert.Nil(t, err)
	}
}

func respondMsgFunc(t *testing.T, msg any) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bytes, err := xml.Marshal(msg)
		assert.Nil(t, err)
		_, err = w.Write(bytes)
		assert.Nil(t, err)
	}
}

func respondStringFunc(t *testing.T, msg string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(msg))
		assert.Nil(t, err)
	}
}

func TestConfigure(t *testing.T) {
	f := &flags.Flags{}

	t.Run("returns InvalidParameters with no sub command and not wifi configs", func(t *testing.T) {
		lps := setupWsmanResponses(t, f, ResponseFuncArray{})
		resultCode := lps.Configure()
		assert.Equal(t, utils.InvalidParameters, resultCode)
	})
	t.Run("returns WiFiConfigurationFailed handling WifiConfigs from LocalConfig", func(t *testing.T) {
		f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{})) // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, wifi.PullEnvelope{}))        // PruneWifiConfigs
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.Configure()
		assert.Equal(t, utils.WiFiConfigurationFailed, resultCode)
	})
}

func TestConfigureWiFi(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	t.Run("expect Success on happy path", func(t *testing.T) {
		pcsRsp := wifiportconfiguration.PortConfigurationResponse{}
		pcsRsp.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{})) // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, wifi.PullEnvelope{}))        // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, pcsRsp))
		responsers = append(responsers, respondMsgFunc(t, wifi.RequestStateChangeResponse{}))
		responsers = append(responsers, respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ConfigureWiFi()
		assert.Equal(t, utils.Success, resultCode)
	})
	t.Run("expect WiFiConfigurationFailed on error with configuration", func(t *testing.T) {
		orig := f.LocalConfig.WifiConfigs[0].ProfileName
		f.LocalConfig.WifiConfigs[0].ProfileName = "bad-name"
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{})) // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, wifi.PullEnvelope{}))        // PruneWifiConfigs
		responsers = append(responsers, respondMsgFunc(t, wifiportconfiguration.PortConfigurationResponse{}))
		responsers = append(responsers, respondMsgFunc(t, wifi.RequestStateChangeResponse{}))
		responsers = append(responsers, respondMsgFunc(t, wifiportconfiguration.AddWiFiSettingsResponse{}))
		lps := setupWsmanResponses(t, f, responsers)
		resultCode := lps.ConfigureWiFi()
		assert.Equal(t, utils.WiFiConfigurationFailed, resultCode)
		f.LocalConfig.WifiConfigs[0].ProfileName = orig
	})
}

func TestProcessWifiConfig(t *testing.T) {
	f := &flags.Flags{}

	// bad name error already tested
	t.Run("expect error ProcessIeee8012xConfig", func(t *testing.T) {
		orig := wifiCfgWPA8021xEAPTLS.AuthenticationMethod
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = int(models.AuthenticationMethod_WPA_IEEE8021x)
		f.LocalConfig.Ieee8021xConfigs = config.Ieee8021xConfigs{}
		f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.ProcessWifiConfig(&wifiCfgWPA8021xEAPTLS)
		assert.NotNil(t, err)
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = orig
	})
	t.Run("expect server error for AddWiFiSettings()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.NotNil(t, err)
	})
	t.Run("expect xml parse error for AddWiFiSettings()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.NotNil(t, err)
	})
	t.Run("expect unsuccessful return value error for AddWiFiSettings()", func(t *testing.T) {
		msgRsp := wifiportconfiguration.AddWiFiSettingsResponse{}
		msgRsp.Body.AddWiFiSettings_OUTPUT.ReturnValue = 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, msgRsp))
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.NotNil(t, err)
	})
}

func TestPruneWifiConfigs(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect success when there are no configs", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, wifi.EnumerationEnvelope{}))
		responsers = append(responsers, respondMsgFunc(t, wifi.PullEnvelope{}))
		lps := setupWsmanResponses(t, f, responsers)
		errCode := lps.PruneWifiConfigs()
		assert.Equal(t, 0, errCode)
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
		assert.Equal(t, 0, errCode)
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
		err := lps.ProcessIeee8012xConfig("someothername", ieee8021xSettings, &handles)
		assert.NotNil(t, err)
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
		err := lps.ProcessIeee8012xConfig(ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName, ieee8021xSettings, &handles)
		assert.NotNil(t, err)
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
		err := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.NotNil(t, err)
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
		err := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.NotNil(t, err)
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
		err := lps.ProcessIeee8012xConfig(ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings, &handles)
		assert.Nil(t, err)
		assert.Equal(t, ieee8021xCfgEAPTLS.ProfileName, ieee8021xSettings.ElementName)
		assert.NotEmpty(t, handles.privateKeyHandle)
		assert.NotEmpty(t, handles.clientCertHandle)
		assert.NotEmpty(t, handles.rootCertHandle)
	})
}

func TestEnableWifiErrors(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect server error for WiFiPortConfigurationService.Get()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
	})
	t.Run("expect unmarshall error for WiFiPortConfigurationService.Get()", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
	})
	t.Run("expect server error for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
	})
	t.Run("expect unmarshall error for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
	})
	t.Run("expect non-zero error for WiFiPortConfigurationService.Put()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseFailed := wifiportconfiguration.PortConfigurationResponse{}
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseFailed))
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
	})
	t.Run("expect server error for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseEnabled))
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
	})
	t.Run("expect xml unmarshall error for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseEnabled))
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
	})
	t.Run("expect non-zero error for RequestStateChange()", func(t *testing.T) {
		pcsResponse := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled := wifiportconfiguration.PortConfigurationResponse{}
		pcsResponseEnabled.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled = 1
		stateChangeResponse := wifi.RequestStateChangeResponse{}
		stateChangeResponse.Body.RequestStateChange_OUTPUT.ReturnValue = 1
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondMsgFunc(t, pcsResponse))
		responsers = append(responsers, respondMsgFunc(t, pcsResponseEnabled))
		responsers = append(responsers, respondMsgFunc(t, stateChangeResponse))
		lps := setupWsmanResponses(t, f, responsers)
		err := lps.EnableWifi()
		assert.NotNil(t, err)
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
	t.Run("expect server error", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddTrustedRootCert("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
	t.Run("expect xml parse error", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddTrustedRootCert("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(trustedRootXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, dup))
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddTrustedRootCert("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
}

func TestAddClientCert(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect server error", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddClientCert("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
	t.Run("expect xml parse error", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddClientCert("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(clientCertXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, dup))
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddClientCert("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
}

func TestAddPrivateKey(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect server error", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondServerErrFunc())
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddPrivateKey("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
	t.Run("expect xml parse error", func(t *testing.T) {
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondBadXmlFunc(t))
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddPrivateKey("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
	t.Run("expect non-zero error ", func(t *testing.T) {
		dup := strings.Replace(addKeyXMLResponse, `<g:ReturnValue>0</g:ReturnValue>`, `<g:ReturnValue>1</g:ReturnValue>`, 1)
		responsers := ResponseFuncArray{}
		responsers = append(responsers, respondStringFunc(t, dup))
		lps := setupWsmanResponses(t, f, responsers)
		handle, err := lps.AddPrivateKey("AABBCCDD")
		assert.NotNil(t, err)
		assert.Empty(t, handle)
	})
}

func TestCheckReturnValue(t *testing.T) {
	tests := []struct {
		name    string
		in      int
		item    string
		wantErr error
	}{
		{"TestNoError", 0, "item", nil},
		{"TestAlreadyExists", common.PT_STATUS_DUPLICATE, "item", fmt.Errorf("%s already exists and must be removed before continuing", "item")},
		{"TestInvalidItem", common.PT_STATUS_INVALID_CERT, "item", fmt.Errorf("%s is invalid", "item")},
		{"TestNonZeroReturnCode", 9999, "item", fmt.Errorf("%s non-zero return code: %d", "item", 9999)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := checkReturnValue(tt.in, tt.item)

			if (gotErr != nil && tt.wantErr == nil) || (gotErr == nil && tt.wantErr != nil) || (gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error()) {
				t.Errorf("gotErr %v, wantErr %v", gotErr, tt.wantErr)
			}
		})
	}
}
