package local

import (
	"github.com/stretchr/testify/assert"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"strings"
	"testing"
	"time"
)

func TestSynchronizeTime(t *testing.T) {
	t.Run("expect success for happy path", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, getLowAccuracyTimeSynchXMLResponse),
			respondStringFunc(t, setHighAccuracyTimeSynchXMLResponse),
		}
		f := &flags.Flags{}
		lps := setupWsmanResponses(t, f, r)
		rc := lps.SynchronizeTime()
		assert.Equal(t, utils.Success, rc)
	})
}

func runGetLowAccuracyTimeSynchTest(t *testing.T, expectedRC utils.ReturnCode, expectedTa0 int64, responsers ResponseFuncArray) {
	f := &flags.Flags{}
	lps := setupWsmanResponses(t, f, responsers)
	ta0, rc := lps.GetLowAccuracyTimeSynch()
	assert.Equal(t, expectedRC, rc)
	assert.Equal(t, expectedTa0, ta0)
}

func TestGetLowAccuracyTimeSynch(t *testing.T) {
	t.Run("expect error at PostAndUnmarshal", func(t *testing.T) {
		r := ResponseFuncArray{
			respondServerErrFunc(),
		}
		runGetLowAccuracyTimeSynchTest(t, utils.WSMANMessageError, 0, r)
	})
	t.Run("expect error on bad ReturnValue", func(t *testing.T) {
		rsp := strings.Replace(getLowAccuracyTimeSynchXMLResponse,
			`<g:ReturnValue>0</g:ReturnValue>`,
			`<g:ReturnValue>1</g:ReturnValue>`, 1)
		expectRC := utils.AmtPtStatusCodeBase + utils.ReturnCode(1)
		r := ResponseFuncArray{
			respondStringFunc(t, rsp),
		}
		runGetLowAccuracyTimeSynchTest(t, expectRC, 0, r)
	})
	t.Run("expect success", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, getLowAccuracyTimeSynchXMLResponse),
		}
		runGetLowAccuracyTimeSynchTest(t, utils.Success, 1704394160, r)
	})
}

func runSetHighAccuracyTimeSynchTest(t *testing.T, expectedRC utils.ReturnCode, ta0 int64, responsers ResponseFuncArray) {
	f := &flags.Flags{}
	lps := setupWsmanResponses(t, f, responsers)
	rc := lps.SetHighAccuracyTimeSynch(ta0)
	assert.Equal(t, expectedRC, rc)
}

func TestSetHighAccuracyTimeSynch(t *testing.T) {
	ta0 := time.Now().Unix()
	t.Run("expect error at PostAndUnmarshal", func(t *testing.T) {
		r := ResponseFuncArray{
			respondServerErrFunc(),
		}
		runSetHighAccuracyTimeSynchTest(t, utils.WSMANMessageError, ta0, r)
	})
	t.Run("expect error on bad ReturnValue", func(t *testing.T) {
		rsp := strings.Replace(setHighAccuracyTimeSynchXMLResponse,
			`<g:ReturnValue>0</g:ReturnValue>`,
			`<g:ReturnValue>1</g:ReturnValue>`, 1)
		expectRC := utils.AmtPtStatusCodeBase + utils.ReturnCode(1)
		r := ResponseFuncArray{
			respondStringFunc(t, rsp),
		}
		runSetHighAccuracyTimeSynchTest(t, expectRC, ta0, r)
	})
	t.Run("expect success", func(t *testing.T) {
		r := ResponseFuncArray{
			respondStringFunc(t, setHighAccuracyTimeSynchXMLResponse),
		}
		runSetHighAccuracyTimeSynchTest(t, utils.Success, ta0, r)
	})
}

const getLowAccuracyTimeSynchXMLResponse = `<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope"
            xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TimeSynchronizationService"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>0</b:RelatesTo>
        <b:Action a:mustUnderstand="true">
            http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TimeSynchronizationService/GetLowAccuracyTimeSynchResponse
        </b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-000000011E1F</b:MessageID>
        <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TimeSynchronizationService</c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:GetLowAccuracyTimeSynch_OUTPUT>
            <g:Ta0>1704394160</g:Ta0>
            <g:ReturnValue>0</g:ReturnValue>
        </g:GetLowAccuracyTimeSynch_OUTPUT>
    </a:Body>
</a:Envelope>`

const setHighAccuracyTimeSynchXMLResponse = `
<?xml version="1.0" encoding="UTF-8"?>
<a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope" xmlns:b="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:c="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/02/trust"
            xmlns:e="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:f="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
            xmlns:g="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TimeSynchronizationService"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <a:Header>
        <b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>
        <b:RelatesTo>9</b:RelatesTo>
        <b:Action a:mustUnderstand="true">
            http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TimeSynchronizationService/SetHighAccuracyTimeSynchResponse
        </b:Action>
        <b:MessageID>uuid:00000000-8086-8086-8086-000000000061</b:MessageID>
        <c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TimeSynchronizationService</c:ResourceURI>
    </a:Header>
    <a:Body>
        <g:SetHighAccuracyTimeSynch_OUTPUT>
            <g:ReturnValue>0</g:ReturnValue>
        </g:SetHighAccuracyTimeSynch_OUTPUT>
    </a:Body>
</a:Envelope>
`
