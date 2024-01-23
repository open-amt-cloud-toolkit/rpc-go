package local

import (
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/tls"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	"github.com/stretchr/testify/assert"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"strings"
	"testing"
)

func runConfigureTLSTest(t *testing.T, expectedCode utils.ReturnCode, responsers ResponseFuncArray) {
	f := &flags.Flags{}
	f.ConfigTLSInfo.DelayInSeconds = 0
	lps := setupWsmanResponses(t, f, responsers)
	rc := lps.ConfigureTLS()
	assert.Equal(t, expectedCode, rc)
}

func TestConfigureTLS(t *testing.T) {
	enumRsp := common.EnumerationResponse{}

	t.Run("expect error at AddTrustedRootCert", func(t *testing.T) {
		r := ResponseFuncArray{}
		runConfigureTLSTest(t, utils.WSMANMessageError, r)
	})

	t.Run("expect error at GenerateKeyPair", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, trustedRootXMLResponse),
		}
		runConfigureTLSTest(t, utils.WSMANMessageError, r)
	})

	t.Run("expect error at GetPublicPrivateKeyPairs", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, trustedRootXMLResponse),
			respondStringFunc(t, generateKeyPairXMLResponse),
		}
		runConfigureTLSTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect error at der key not found after GetPublicPrivateKeyPairs", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, trustedRootXMLResponse),
			respondStringFunc(t, generateKeyPairXMLResponse),
			respondMsgFunc(t, enumRsp),
			respondMsgFunc(t, publicprivate.PullResponseEnvelope{}),
		}
		runConfigureTLSTest(t, utils.TLSConfigurationFailed, r)
	})
	t.Run("expect error at AddClientCert", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, trustedRootXMLResponse),
			respondStringFunc(t, generateKeyPairXMLResponse),
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, publicPrivateKeyPairXMLResponse),
		}
		runConfigureTLSTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect error at CreateTLSCredentialContext", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, trustedRootXMLResponse),
			respondStringFunc(t, generateKeyPairXMLResponse),
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, publicPrivateKeyPairXMLResponse),
			respondStringFunc(t, addClientCertXMLResponse),
		}
		runConfigureTLSTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect error at SyncTime", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, trustedRootXMLResponse),
			respondStringFunc(t, generateKeyPairXMLResponse),
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, publicPrivateKeyPairXMLResponse),
			respondStringFunc(t, addClientCertXMLResponse),
			respondStringFunc(t, credCtxPullRspString),
		}
		runConfigureTLSTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect success for happy path", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, trustedRootXMLResponse),
			respondStringFunc(t, generateKeyPairXMLResponse),
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, publicPrivateKeyPairXMLResponse),
			respondStringFunc(t, addClientCertXMLResponse),
			respondStringFunc(t, credCtxPullRspString),
			respondStringFunc(t, getLowAccuracyTimeSynchXMLResponse),
			respondStringFunc(t, setHighAccuracyTimeSynchXMLResponse),
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, tlsSettingsXMLResponse),
			respondStringFunc(t, putTLSSettingsXMLResponse),
			respondStringFunc(t, putTLSSettingsXMLResponse),
			respondStringFunc(t, commitChangesXMLResponse),
		}
		runConfigureTLSTest(t, utils.Success, r)
	})
}

func runGenerateKeyPairTest(t *testing.T, expectedHandle string, expectedCode utils.ReturnCode, responsers ResponseFuncArray) {
	f := &flags.Flags{}
	lps := setupWsmanResponses(t, f, responsers)
	handle, rc := lps.GenerateKeyPair()
	assert.Equal(t, expectedCode, rc)
	assert.Equal(t, expectedHandle, handle)
}

func TestGenerateKeyPair(t *testing.T) {

	t.Run("expect failure on non-success return code", func(t *testing.T) {
		rsp := publickey.Response{}
		rsp.Body.GeneratedKeyPair_OUTPUT.ReturnValue = 1
		expected := utils.AmtPtStatusCodeBase + utils.ReturnCode(rsp.Body.GeneratedKeyPair_OUTPUT.ReturnValue)
		r := ResponseFuncArray{
			respondMsgFunc(t, rsp),
		}
		runGenerateKeyPairTest(t, "", expected, r)
	})
	t.Run("expect failure on non-success return code", func(t *testing.T) {
		rsp := publickey.Response{}
		r := ResponseFuncArray{
			respondMsgFunc(t, rsp),
		}
		runGenerateKeyPairTest(t, "", utils.TLSConfigurationFailed, r)
	})
	t.Run("expect success on non-success return code", func(t *testing.T) {
		expectedHandle := "Intel(r) AMT Key: Handle: 3"
		r := ResponseFuncArray{
			respondStringFunc(t, generateKeyPairXMLResponse),
		}
		runGenerateKeyPairTest(t, expectedHandle, utils.Success, r)
	})
}

func TestCreateCredentialContext(t *testing.T) {
	t.Run("expect success if credential already exists", func(t *testing.T) {
		expectedHandle := "Intel(r) AMT Key: Handle: 3"
		r := ResponseFuncArray{
			respondErrFunc(t, 403, credentialAlreadyExists),
		}
		f := &flags.Flags{}
		lps := setupWsmanResponses(t, f, r)
		rc := lps.CreateTLSCredentialContext(expectedHandle)
		assert.Equal(t, utils.Success, rc)
	})
}

func runEnableTLSTest(t *testing.T, expectedCode utils.ReturnCode, responsers ResponseFuncArray) {
	f := &flags.Flags{}
	f.ConfigTLSInfo.DelayInSeconds = 1
	lps := setupWsmanResponses(t, f, responsers)
	rc := lps.EnableTLS()
	assert.Equal(t, expectedCode, rc)
}

func TestEnableTLS(t *testing.T) {
	enumRsp := common.EnumerationResponse{}
	t.Run("expect error at EnumPullUnmarshal", func(t *testing.T) {
		runEnableTLSTest(t, utils.WSMANMessageError, ResponseFuncArray{})
	})
	t.Run("expect error at ConfigureTLSSettings", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, tlsSettingsXMLResponse),
		}
		runEnableTLSTest(t, utils.WSMANMessageError, r)
	})

	t.Run("expect WSMANMessageError at CommitChanges", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, tlsSettingsXMLResponse),
			respondStringFunc(t, putTLSSettingsXMLResponse),
			respondStringFunc(t, putTLSSettingsXMLResponse),
		}
		runEnableTLSTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect ReturnValue error at CommitChanges", func(t *testing.T) {
		var rspXML = strings.Replace(commitChangesXMLResponse,
			"<g:ReturnValue>0</g:ReturnValue>",
			"<g:ReturnValue>1</g:ReturnValue>",
			1)
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondStringFunc(t, tlsSettingsXMLResponse),
			respondStringFunc(t, putTLSSettingsXMLResponse),
			respondStringFunc(t, putTLSSettingsXMLResponse),
			respondStringFunc(t, rspXML),
		}
		expected := utils.AmtPtStatusCodeBase + utils.ReturnCode(1)
		runEnableTLSTest(t, expected, r)
	})
}

func TestGetTLSSettingsPutData(t *testing.T) {
	t.Run("expect correct local tls settings", func(t *testing.T) {
		setting := tls.TlsSetting{
			AcceptNonSecureConnections: true,
			ElementName:                LocalTLSInstanceId,
			Enabled:                    true,
			InstanceID:                 LocalTLSInstanceId,
			MutualAuthentication:       true,
		}
		expected := tls.TLSSettingData{
			AcceptNonSecureConnections: true,
			ElementName:                LocalTLSInstanceId,
			Enabled:                    true,
			InstanceID:                 LocalTLSInstanceId,
			MutualAuthentication:       true,
		}
		actual := getTLSSettingsPutData(&setting, flags.TLSModeServer)
		assert.Equal(t, expected, actual)
	})
	t.Run("expect correct remote tls settings", func(t *testing.T) {
		setting := tls.TlsSetting{
			AcceptNonSecureConnections: true,
			ElementName:                RemoteTLSInstanceId,
			InstanceID:                 RemoteTLSInstanceId,
			MutualAuthentication:       true,
		}
		expected := tls.TLSSettingData{
			ElementName: RemoteTLSInstanceId,
			Enabled:     true,
			InstanceID:  RemoteTLSInstanceId,
		}

		expected.AcceptNonSecureConnections = false
		expected.MutualAuthentication = false
		actual := getTLSSettingsPutData(&setting, flags.TLSModeServer)
		assert.Equal(t, expected, actual)

		var nonSecureCnx = true
		setting.NonSecureConnectionsSupported = &nonSecureCnx
		expected.AcceptNonSecureConnections = true
		expected.MutualAuthentication = false
		actual = getTLSSettingsPutData(&setting, flags.TLSModeServerAndNonTLS)
		assert.Equal(t, expected, actual)

		expected.AcceptNonSecureConnections = false
		expected.MutualAuthentication = true
		actual = getTLSSettingsPutData(&setting, flags.TLSModeMutual)
		assert.Equal(t, expected, actual)

		expected.AcceptNonSecureConnections = true
		expected.MutualAuthentication = true
		actual = getTLSSettingsPutData(&setting, flags.TLSModeMutualAndNonTLS)
		assert.Equal(t, expected, actual)

	})

}

const generateKeyPairXMLResponse = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>3</b:RelatesTo>
        <b:Action a:mustUnderstand="true">
            http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService/GenerateKeyPairResponse
        </b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-0000000005C5</b:MessageID>
        <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService</c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:GenerateKeyPair_OUTPUT>
            <g:KeyPair>
                <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
                <b:ReferenceParameters>
                    <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair</c:ResourceURI>
                    <c:SelectorSet>
                        <c:Selector Name="InstanceID">Intel(r) AMT Key: Handle: 3</c:Selector>
                    </c:SelectorSet>
                </b:ReferenceParameters>
            </g:KeyPair>
            <g:ReturnValue>0</g:ReturnValue>
        </g:GenerateKeyPair_OUTPUT>
    </a:Body>
</a:Envelope>`

const publicPrivateKeyPairXMLResponse = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair"
            xmlns:i="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>5</b:RelatesTo>
        <b:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse</b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-000000000024</b:MessageID>
        <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair</c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:PullResponse>
            <g:Items>
                <h:AMT_PublicPrivateKeyPair>
                    <h:DERKey>
                        MIIBCgKCAQEA3zEgE1hJ+rK2nnxMUh2/sO+4J39PsPo+97vtmdlJH86yyoP/kFTGu6MABV/ew331jHUhaKPNYczTK2ApWrewD6E5qzeyPhYevRCuA+igysYCRk9Vn59ZQpVFAgoZKtc0AYlc4nWIpZGAw4dxtef8RD7vKrY8+D597XPC+DVANbIS+OhcF7VyChTdx7qVU6xdjiXritVux7iHv0Jy2/VpMcAE9u2XJTW4nERTDhUiuWepDoZouTzR7mbDOusLhLjK348JkK2+IBjagnBmNCPTI02MP8HKAr/0Q9JsKh3ddL7C7mo1f9d385NNG7GZEN/AA1oBmzKVplwEL0uw5ITG7wIDAQAB
                    </h:DERKey>
                    <h:ElementName>Intel(r) AMT Key</h:ElementName>
                    <h:InstanceID>Intel(r) AMT Key: Handle: 0</h:InstanceID>
                </h:AMT_PublicPrivateKeyPair>
                <h:AMT_PublicPrivateKeyPair>
                    <h:DERKey>
                        MIIBCgKCAQEAwX77L32ccNNmllIk9O5h+DG740iO56rzAmjo63F8KU51k7cudZB5RKcQwIiqBwHuKdzhAlWVpKPLWFLIrOwTCnMwGeSU6okUbctK1vOLg87a5Us78pA4Z8tI8GjlSIhCS7NUwxTVoQasWPCQlek+KpB8JcZOB7qRcIu8wZrXwvHphglmRfGDcONSZaWkYTFaWXaKCLFzJi+094Mp/Ucgu2szrMWqi13bUqHTf6DjXqJ+k+IMCIrEk2vx1mpbz120/ZAEo/pXcBk0hkt+g3Qg3QLHFB6tWGCJoKKyI5ySyZMppKzkgl7paCEDrUsnuew0y41jCTC5+8bPE6Mk3AzGQwIDAQAB
                    </h:DERKey>
                    <h:ElementName>Intel(r) AMT Key</h:ElementName>
                    <h:InstanceID>Intel(r) AMT Key: Handle: 1</h:InstanceID>
                </h:AMT_PublicPrivateKeyPair>
                <h:AMT_PublicPrivateKeyPair>
                    <h:DERKey>
                        MIIBCgKCAQEA2qJUQXfLPBSQjAkj2YyskzcBaYe2BoE5OIDghUf7V0f29a84ulqx1alrsptf3X9cT1mIHhJ2ThBQoE2sqEE/liBpJLExj+sXB78bWPYvxjayJKZmVS95fHPy6Namse8GrYz4sN8U0EQIQ/Mt6Tg+kIharZL+znqZXGDslYLvBr+NYGy97q7JxA2Y69V8eK9D2+2leo1DWLBuLwrJaTxVnkh72q4v6OSVtP3IR3U9lDTt9rehgFLiLbE1ioaQ6eutVyg8vI2l8qr5fPpDVRB/TNa9z98DqNL/rur7y82CCDWwpLgKCBz6qMXfa+EBBNs1cLYVGHhn9+AqKxrha356PQIDAQAB
                    </h:DERKey>
                    <h:ElementName>Intel(r) AMT Key</h:ElementName>
                    <h:InstanceID>Intel(r) AMT Key: Handle: 2</h:InstanceID>
                </h:AMT_PublicPrivateKeyPair>
                <h:AMT_PublicPrivateKeyPair>
                    <h:DERKey>
                        MIIBCgKCAQEArYLhHgyZXGU8rt88sSWmuy+e/Qz/arN+2DcLM8KHdJSewfD8h8Ydk4S1z00+y4AmnVUYYC8JChu+BtuNGlAdEKbo36hySH9a5BGuUn8uPnZGpkCLAD2wbXfmoSk9ReGgC5q+ScpQdtDq0C/e/eHUDc+2fUdPAri4Zx4Ot/6vyq1YSKvGr8eiO91v4IA0r8sdJETrtAtJ/hDz131JJBXadRhrOteqc30TYohqdRxN2JNOeXNAT1McNBJBnqcsRF6BSK8V4wMbA+qCvazN3byyJ1kq/GKX5W8e3cMvzWCXil58oiEvsXkMBc938omXc+TQDzl9biP3pSNhg3Wvh7AKywIDAQAB
                    </h:DERKey>
                    <h:ElementName>Intel(r) AMT Key</h:ElementName>
                    <h:InstanceID>Intel(r) AMT Key: Handle: 3</h:InstanceID>
                </h:AMT_PublicPrivateKeyPair>
            </g:Items>
            <g:EndOfSequence></g:EndOfSequence>
        </g:PullResponse>
    </a:Body>
</a:Envelope>`

const addClientCertXMLResponse = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope
        xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
        xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
        xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
        xmlns:g="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>6</b:RelatesTo>
        <b:Action a:mustUnderstand=
                          "true">
            http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService/AddCertificateResponse
        </b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-000000000025</b:MessageID>
        <c:ResourceURI>
            http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService
        </c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:AddCertificate_OUTPUT>
            <g:CreatedCertificate>
                <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
                <b:ReferenceParameters>
                    <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI>
                    <c:SelectorSet>
                        <c:Selector Name="InstanceID">Intel(r) AMT Certificate: Handle: 7
                        </c:Selector>
                    </c:SelectorSet>
                </b:ReferenceParameters>
            </g:CreatedCertificate>
            <g:ReturnValue>0</g:ReturnValue>
        </g:AddCertificate_OUTPUT>
    </a:Body>
</a:Envelope>`

const tlsSettingsXMLResponse = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope"
            xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TLSSettingData"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>12</b:RelatesTo>
        <b:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse</b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-0000000000FC</b:MessageID>
        <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TLSSettingData</c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:PullResponse>
            <g:Items>
                <h:AMT_TLSSettingData>
                    <h:AcceptNonSecureConnections>false</h:AcceptNonSecureConnections>
                    <h:ElementName>Intel(r) AMT 802.3 TLS Settings</h:ElementName>
                    <h:Enabled>true</h:Enabled>
                    <h:InstanceID>Intel(r) AMT 802.3 TLS Settings</h:InstanceID>
                    <h:MutualAuthentication>false</h:MutualAuthentication>
                    <h:NonSecureConnectionsSupported>false</h:NonSecureConnectionsSupported>
                </h:AMT_TLSSettingData>
                <h:AMT_TLSSettingData>
                    <h:AcceptNonSecureConnections>true</h:AcceptNonSecureConnections>
                    <h:ElementName>Intel(r) AMT LMS TLS Settings</h:ElementName>
                    <h:Enabled>true</h:Enabled>
                    <h:InstanceID>Intel(r) AMT LMS TLS Settings</h:InstanceID>
                    <h:MutualAuthentication>false</h:MutualAuthentication>
                    <h:NonSecureConnectionsSupported>true</h:NonSecureConnectionsSupported>
                </h:AMT_TLSSettingData>
            </g:Items>
            <g:EndOfSequence></g:EndOfSequence>
        </g:PullResponse>
    </a:Body>
</a:Envelope>
`
const putTLSSettingsXMLResponse = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope
        xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
        xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
        xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
        xmlns:g="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TLSSettingData"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>40</b:RelatesTo>
        <b:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse
        </b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-00000000008E</b:MessageID>
        <c:ResourceURI>
            http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TLSSettingData
        </c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:AMT_TLSSettingData>
            <g:AcceptNonSecureConnections>true</g:AcceptNonSecureConnections>
            <g:ElementName>Intel(r) AMT LMS TLS Settings</g:ElementName>
            <g:Enabled>false</g:Enabled>
            <g:InstanceID>Intel(r) AMT LMS TLS Settings</g:InstanceID>
            <g:MutualAuthentication>false</g:MutualAuthentication>
            <g:NonSecureConnectionsSupported>true</g:NonSecureConnectionsSupported>
        </g:AMT_TLSSettingData>
    </a:Body>
</a:Envelope>
`

const commitChangesXMLResponse = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SetupAndConfigurationService"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>11</b:RelatesTo>
        <b:Action a:mustUnderstand="true">
            http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SetupAndConfigurationService/CommitChangesResponse
        </b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-00000000BE73</b:MessageID>
        <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SetupAndConfigurationService</c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:CommitChanges_OUTPUT>
            <g:ReturnValue>0</g:ReturnValue>
        </g:CommitChanges_OUTPUT>
    </a:Body>
</a:Envelope>
`

const credentialAlreadyExists = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:g="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:f="http://schemas.xmlsoap.org/ws/2004/08/eventing"
            xmlns:e="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2004/09/transfer"
            xmlns:c="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:a="http://www.w3.org/2003/05/soap-envelope"
            xmlns:h="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:i="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>36</b:RelatesTo>
        <b:Action a:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-000000000084</b:MessageID>
    </a:Header>
    <a:Body>
        <a:Fault>
            <a:Code>
                <a:Value>a:Sender</a:Value>
                <a:Subcode>
                    <a:Value>e:AlreadyExists</a:Value>
                </a:Subcode>
            </a:Code>
            <a:Reason>
                <a:Text xml:lang="en-US">The sender attempted to create a resource which already exists.</a:Text>
            </a:Reason>
            <a:Detail></a:Detail>
        </a:Fault>
    </a:Body>
</a:Envelope>
`
