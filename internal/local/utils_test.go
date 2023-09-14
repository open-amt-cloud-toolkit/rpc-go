package local

import (
	"regexp"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	"github.com/stretchr/testify/assert"
)

var mpsCert = publickey.PublicKeyCertificate{
	ElementName:           "Intel(r) AMT Certificate",
	InstanceID:            "Intel(r) AMT Certificate: Handle: 0",
	X509Certificate:       `MIIEkzCCA3ugAwIBAgIUL3WtF7HfMKxQOHcZy65Z0tsSoLwwDQYJKoZIhvc`,
	TrustedRootCertficate: true,
	Issuer:                "C=unknown,O=unknown,CN=MPSRoot-5bb511",
	Subject:               "C=unknown,O=unknown,CN=MPSRoot-5bb511",
	ReadOnlyCertificate:   true,
}
var caCert = publickey.PublicKeyCertificate{
	ElementName:           "Intel(r) AMT Certificate",
	InstanceID:            "Intel(r) AMT Certificate: Handle: 1",
	X509Certificate:       `CERTHANDLE1MIIEkzCCA3ugAwIBAgIUL3WtF7HfMKxQOHcZy65Z0tsSoLwwDQYJKoZIhvc`,
	TrustedRootCertficate: true,
	Issuer:                `C=US,S=Arizona,L=Chandler,CN=Unit Tests Are Us`,
	Subject:               `C=US,S=Arizona,L=Chandler,CN=Unit Test CA Root Certificate`,
}
var clientCert = publickey.PublicKeyCertificate{
	ElementName:           "Intel(r) AMT Certificate",
	InstanceID:            "Intel(r) AMT Certificate: Handle: 3",
	X509Certificate:       `CERTHANDLE2AwIBAgIUBgF0PsmOxA/KJVDCcbW+n5IbemgwDQYJKoZIhvc`,
	TrustedRootCertficate: false,
	Issuer:                `C=US,S=Arizona,L=Chandler,CN=Unit Tests Are Us`,
	Subject:               `C=US,S=Arizona,L=Chandler,CN=Unit Test Client Certificate`,
	ReadOnlyCertificate:   true,
}
var keyPair01 = publicprivate.PublicPrivateKeyPair{
	ElementName: "Intel(r) AMT Key",
	InstanceID:  "Intel(r) AMT Key: Handle: 0",
	DERKey:      `MIIBCgKCAQEA37Xwr/oVLFftw+2wkmwdzGaufBnLiwJCXwYrWLMld1+7Ve6DghlFPa+Mr`,
}

func runGetPublicKeyCertTest(t *testing.T, expectedCode utils.ReturnCode, responsers ResponseFuncArray) {
	f := &flags.Flags{}
	lps := setupWsmanResponses(t, f, responsers)
	var certs []publickey.PublicKeyCertificate
	rc := lps.GetPublicKeyCerts(&certs)
	assert.Equal(t, expectedCode, rc)
	assert.Empty(t, certs)
}

func TestGetPublicKeyCerts(t *testing.T) {
	enumRsp := common.EnumerationResponse{}
	t.Run("expect WSMANMessageError for Enumerate call", func(t *testing.T) {
		r := ResponseFuncArray{respondServerErrFunc()}
		runGetPublicKeyCertTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect UnmarshalMessageFailed for Enumerate call", func(t *testing.T) {
		r := ResponseFuncArray{respondBadXmlFunc(t)}
		runGetPublicKeyCertTest(t, utils.UnmarshalMessageFailed, r)
	})
	t.Run("expect WSMANMessageError for Pull call", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondServerErrFunc(),
		}
		runGetPublicKeyCertTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect UnmarshalMessageFailed for Pull call", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondBadXmlFunc(t),
		}
		runGetPublicKeyCertTest(t, utils.UnmarshalMessageFailed, r)
	})
	t.Run("expect Success for happy path (with no certs)", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondMsgFunc(t, publickey.PullResponseEnvelope{}),
		}
		runGetPublicKeyCertTest(t, utils.Success, r)
	})
}

func runGetPublicPrivateKeyPairsTest(t *testing.T, expectedCode utils.ReturnCode, responsers ResponseFuncArray) {
	f := &flags.Flags{}
	lps := setupWsmanResponses(t, f, responsers)
	var keyPairs []publicprivate.PublicPrivateKeyPair
	rc := lps.GetPublicPrivateKeyPairs(&keyPairs)
	assert.Equal(t, expectedCode, rc)
	assert.Empty(t, keyPairs)
}

func TestGetPublicPrivateKeyPairs(t *testing.T) {
	enumRsp := common.EnumerationResponse{}
	t.Run("expect WSMANMessageError for Enumerate call", func(t *testing.T) {
		r := ResponseFuncArray{respondServerErrFunc()}
		runGetPublicPrivateKeyPairsTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect UnmarshalMessageFailed for Enumerate call", func(t *testing.T) {
		r := ResponseFuncArray{respondBadXmlFunc(t)}
		runGetPublicPrivateKeyPairsTest(t, utils.UnmarshalMessageFailed, r)
	})
	t.Run("expect WSMANMessageError for Pull call", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondServerErrFunc(),
		}
		runGetPublicPrivateKeyPairsTest(t, utils.WSMANMessageError, r)
	})
	t.Run("expect UnmarshalMessageFailed for Pull call", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondBadXmlFunc(t),
		}
		runGetPublicPrivateKeyPairsTest(t, utils.UnmarshalMessageFailed, r)
	})
	t.Run("expect Success for happy path (with no certs)", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, enumRsp),
			respondMsgFunc(t, publicprivate.PullResponseEnvelope{}),
		}
		runGetPublicPrivateKeyPairsTest(t, utils.Success, r)
	})
}

func TestDeletePublicPrivateKeyPair(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect Success for happy path", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, "response does not matter"),
		}
		lps := setupWsmanResponses(t, f, r)
		rc := lps.DeletePublicPrivateKeyPair("some instance Id")
		assert.Equal(t, utils.Success, rc)
	})
	t.Run("expect DeleteWifiConfigFailed error", func(t *testing.T) {
		r := ResponseFuncArray{
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, r)
		rc := lps.DeletePublicPrivateKeyPair("some instance Id")
		assert.Equal(t, utils.DeleteWifiConfigFailed, rc)
	})
}

func TestDeletePublicCert(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect Success for happy path", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, "response does not matter"),
		}
		lps := setupWsmanResponses(t, f, r)
		rc := lps.DeletePublicCert("some instance Id")
		assert.Equal(t, utils.Success, rc)
	})
	t.Run("expect DeleteWifiConfigFailed error", func(t *testing.T) {
		r := ResponseFuncArray{
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, r)
		rc := lps.DeletePublicCert("some instance Id")
		assert.Equal(t, utils.DeleteWifiConfigFailed, rc)
	})
}

func TestGetCredentialRelationships(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect Success for happy path", func(t *testing.T) {
		re := regexp.MustCompile(enumCtxElement)
		pullRspNoEnumCtx := re.ReplaceAllString(credCtxPullRspString, endOfSequenceElement)
		r := ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondStringFunc(t, credCtxPullRspString),
			respondStringFunc(t, pullRspNoEnumCtx),
		}
		lps := setupWsmanResponses(t, f, r)
		credentials, rc := lps.GetCredentialRelationships()
		assert.Equal(t, utils.Success, rc)
		assert.Equal(t, 4, len(credentials))
	})
	t.Run("expect WSMANMessageError on second pull", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondStringFunc(t, credCtxPullRspString),
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, r)
		credentials, rc := lps.GetCredentialRelationships()
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Equal(t, 2, len(credentials))
	})
	t.Run("expect WSMANMessageError on EnumPullUnmarshal() error", func(t *testing.T) {
		r := ResponseFuncArray{
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, r)
		credentials, rc := lps.GetCredentialRelationships()
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Empty(t, credentials)
	})
}

func TestGetConcreteDependencies(t *testing.T) {
	f := &flags.Flags{}
	t.Run("expect Success for happy path", func(t *testing.T) {
		re := regexp.MustCompile(enumCtxElement)
		pullRspNoEnumCtx := re.ReplaceAllString(concreteDependencyPullRspString, endOfSequenceElement)
		r := ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondStringFunc(t, concreteDependencyPullRspString),
			respondStringFunc(t, pullRspNoEnumCtx),
		}
		lps := setupWsmanResponses(t, f, r)
		credentials, rc := lps.GetConcreteDependencies()
		assert.Equal(t, utils.Success, rc)
		assert.Equal(t, 6, len(credentials))
	})
	t.Run("expect WSMANMessageError on second pull", func(t *testing.T) {
		r := ResponseFuncArray{
			respondMsgFunc(t, common.EnumerationResponse{}),
			respondStringFunc(t, concreteDependencyPullRspString),
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, r)
		credentials, rc := lps.GetConcreteDependencies()
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Equal(t, 3, len(credentials))
	})
	t.Run("expect WSMANMessageError on EnumPullUnmarshal() error", func(t *testing.T) {
		r := ResponseFuncArray{
			respondServerErrFunc(),
		}
		lps := setupWsmanResponses(t, f, r)
		credentials, rc := lps.GetConcreteDependencies()
		assert.Equal(t, utils.WSMANMessageError, rc)
		assert.Empty(t, credentials)
	})
}

var enumCtxElement = `<g:EnumerationContext>84730100-0000-0000-0000-000000000000</g:EnumerationContext>`
var endOfSequenceElement = `<g:EndOfSequence></g:EndOfSequence>`

var credCtxPullRspString = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:h="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_CredentialContext"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <a:Header>
    <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
    <b:RelatesTo>3</b:RelatesTo>
    <b:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse</b:Action>
    <b:MessageID>uuid:00000000-8086-8086-8086-0000000472D9</b:MessageID>
    <c:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_CredentialContext</c:ResourceURI>
  </a:Header>
  <a:Body>
    <g:PullResponse>` +
	enumCtxElement +
	`<g:Items>
        <h:CIM_CredentialContext>
          <h:ElementInContext>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT Certificate: Handle: 2</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:ElementInContext>
          <h:ElementProvidingContext>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT:IEEE 802.1x Settings wifi8021x</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:ElementProvidingContext>
        </h:CIM_CredentialContext>
        <h:CIM_CredentialContext>
          <h:ElementInContext>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT Certificate: Handle: 1</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:ElementInContext>
          <h:ElementProvidingContext>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT:IEEE 802.1x Settings wifi8021x</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:ElementProvidingContext>
        </h:CIM_CredentialContext>
      </g:Items>
    </g:PullResponse>
  </a:Body>
</a:Envelope>
`

var concreteDependencyPullRspString = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:h="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ConcreteDependency"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <a:Header>
    <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
    <b:RelatesTo>5</b:RelatesTo>
    <b:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse</b:Action>
    <b:MessageID>uuid:00000000-8086-8086-8086-0000000473A3</b:MessageID>
    <c:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ConcreteDependency</c:ResourceURI>
  </a:Header>
  <a:Body>
    <g:PullResponse>
` + enumCtxElement + `
	<g:Items>
        <h:CIM_ConcreteDependency>
          <h:Antecedent>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AssetTableService</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="CreationClassName">AMT_AssetTableService</c:Selector>
                <c:Selector Name="Name">Intel(r) AMT Asset Table Service</c:Selector>
                <c:Selector Name="SystemCreationClassName">CIM_ComputerSystem</c:Selector>
                <c:Selector Name="SystemName">Intel(r) AMT</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:Antecedent>
          <h:Dependent>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AssetTable</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">1</c:Selector>
                <c:Selector Name="TableType">131</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:Dependent>
        </h:CIM_ConcreteDependency>
        <h:CIM_ConcreteDependency>
          <h:Antecedent>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT Certificate: Handle: 1</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:Antecedent>
          <h:Dependent>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT Key: Handle: 0</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:Dependent>
        </h:CIM_ConcreteDependency>
        <h:CIM_ConcreteDependency>
          <h:Antecedent>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT Certificate: Handle: 1</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:Antecedent>
          <h:Dependent>
            <b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address>
            <b:ReferenceParameters>
              <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SOME_UNHANDLED_RESOURCE_FOR_TESTING</c:ResourceURI>
              <c:SelectorSet>
                <c:Selector Name="InstanceID">Intel(r) AMT Key: Handle: 0</c:Selector>
              </c:SelectorSet>
            </b:ReferenceParameters>
          </h:Dependent>
        </h:CIM_ConcreteDependency>
      </g:Items>
    </g:PullResponse>
  </a:Body>
</a:Envelope>
`
