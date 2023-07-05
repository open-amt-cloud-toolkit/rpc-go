package local

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"rpc/internal/config"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman"
)

const trustedRootXMLResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:e=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:f=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><a:Header><b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To><b:RelatesTo>2</b:RelatesTo><b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService/AddTrustedRootCertificateResponse</b:Action><b:MessageID>uuid:00000000-8086-8086-8086-00000003A988</b:MessageID><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService</c:ResourceURI></a:Header><a:Body><g:AddTrustedRootCertificate_OUTPUT><g:CreatedCertificate><b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address><b:ReferenceParameters><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI><c:SelectorSet><c:Selector Name=\"InstanceID\">Intel(r) AMT Certificate: Handle: 2</c:Selector></c:SelectorSet></b:ReferenceParameters></g:CreatedCertificate><g:ReturnValue>0</g:ReturnValue></g:AddTrustedRootCertificate_OUTPUT></a:Body></a:Envelope>"
const clientCertXMLResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:e=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:f=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><a:Header><b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To><b:RelatesTo>1</b:RelatesTo><b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService/AddCertificateResponse</b:Action><b:MessageID>uuid:00000000-8086-8086-8086-00000003A89C</b:MessageID><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService</c:ResourceURI></a:Header><a:Body><g:AddCertificate_OUTPUT><g:CreatedCertificate><b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address><b:ReferenceParameters><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</c:ResourceURI><c:SelectorSet><c:Selector Name=\"InstanceID\">Intel(r) AMT Certificate: Handle: 1</c:Selector></c:SelectorSet></b:ReferenceParameters></g:CreatedCertificate><g:ReturnValue>0</g:ReturnValue></g:AddCertificate_OUTPUT></a:Body></a:Envelope>"
const addKeyXMLResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:e=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:f=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><a:Header><b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To><b:RelatesTo>0</b:RelatesTo><b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService/AddKeyResponse</b:Action><b:MessageID>uuid:00000000-8086-8086-8086-00000003A89B</b:MessageID><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyManagementService</c:ResourceURI></a:Header><a:Body><g:AddKey_OUTPUT><g:CreatedKey><b:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:Address><b:ReferenceParameters><c:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair</c:ResourceURI><c:SelectorSet><c:Selector Name=\"InstanceID\">Intel(r) AMT Key: Handle: 0</c:Selector></c:SelectorSet></b:ReferenceParameters></g:CreatedKey><g:ReturnValue>0</g:ReturnValue></g:AddKey_OUTPUT></a:Body></a:Envelope>"

func setup(t *testing.T, handler http.Handler) LocalConfiguration {
	server := httptest.NewServer(handler)

	config := config.Config{
		// fill with appropriate values
	}

	client := wsman.NewClient(server.URL, "admin", "password", false)

	return NewLocalConfiguration(config, client)
}

func TestConfigure8021xWiFi(t *testing.T) {
	t.Run("returns error when AddPrivateKey fails", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})

		localConf := setup(t, handler)
		err := localConf.Configure8021xWiFi()
		assert.NotNil(t, err)
	})

	t.Run("returns error when AddClientCert fails", func(t *testing.T) {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate AddPrivateKey success and AddClientCert failure
			if calls == 0 {
				calls++
				assert.Equal(t, "POST", r.Method)
				_, err := w.Write([]byte(addKeyXMLResponse))
				assert.Nil(t, err)

			} else {
				assert.Equal(t, "POST", r.Method)
				w.WriteHeader(http.StatusInternalServerError)
			}
		})

		localConf := setup(t, handler)
		err := localConf.Configure8021xWiFi()
		assert.NotNil(t, err)
	})

	t.Run("returns error when AddTrustedRootCert fails", func(t *testing.T) {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate AddPrivateKey and AddClientCert success and AddTrustedRootCert failure
			if calls == 0 {
				calls++
				assert.Equal(t, "POST", r.Method)
				_, err := w.Write([]byte(addKeyXMLResponse))
				assert.Nil(t, err)
			} else if calls == 1 {
				calls++
				assert.Equal(t, "POST", r.Method)
				_, err := w.Write([]byte(clientCertXMLResponse))
				assert.Nil(t, err)
			} else {
				assert.Equal(t, "POST", r.Method)
				w.WriteHeader(http.StatusInternalServerError)
			}
		})

		localConf := setup(t, handler)
		err := localConf.Configure8021xWiFi()
		assert.NotNil(t, err)
	})

	t.Run("returns error when AddWifiSettings fails", func(t *testing.T) {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate AddPrivateKey and AddClientCert success and AddTrustedRootCert failure
			if calls == 0 {
				calls++
				assert.Equal(t, "POST", r.Method)
				_, err := w.Write([]byte(addKeyXMLResponse))
				assert.Nil(t, err)
			} else if calls == 1 {
				calls++
				assert.Equal(t, "POST", r.Method)
				_, err := w.Write([]byte(clientCertXMLResponse))
				assert.Nil(t, err)
			} else if calls == 2 {
				calls++
				assert.Equal(t, "POST", r.Method)
				_, err := w.Write([]byte(trustedRootXMLResponse))
				assert.Nil(t, err)
			} else {
				assert.Equal(t, "POST", r.Method)
				w.WriteHeader(http.StatusInternalServerError)
			}
		})

		localConf := setup(t, handler)
		err := localConf.Configure8021xWiFi()
		assert.NotNil(t, err)
	})

	t.Run("returns error when RollbackAddedItems fails", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate all steps before RollbackAddedItems success and RollbackAddedItems failure
			if strings.Contains(r.URL.Path, "RollbackAddedItems") {
				assert.Equal(t, "POST", r.Method)
				w.WriteHeader(http.StatusInternalServerError)
			} else if strings.Contains(r.URL.Path, "WifiSettings") {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		})

		localConf := setup(t, handler)
		err := localConf.Configure8021xWiFi()
		assert.NotNil(t, err)
	})
}

func TestAddWifiSettings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request method and URL path.
		assert.Equal(t, "POST", r.Method)
		// Return an error response
		w.WriteHeader(http.StatusInternalServerError)
	})

	localConf := setup(t, handler)
	err := localConf.AddWifiSettings("certHandle", "rootHandle")
	assert.NotNil(t, err)

}
func TestRollbackAddedItems(t *testing.T) {
	t.Run("returns no error when rollback is successful", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusOK)
		})

		localConf := setup(t, handler)
		err := localConf.RollbackAddedItems("certHandle", "rootHandle", "privateKeyHandle")
		assert.Nil(t, err)
	})

	t.Run("returns error when server returns non-200 status code", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})

		localConf := setup(t, handler)
		err := localConf.RollbackAddedItems("certHandle", "rootHandle", "privateKeyHandle")
		assert.NotNil(t, err)
	})
}

func TestAddTrustedRootCert(t *testing.T) {
	t.Run("returns handle when adding cert is successful", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, err := w.Write([]byte(trustedRootXMLResponse))
			assert.Nil(t, err)
		})

		localConf := setup(t, handler)
		handle, err := localConf.AddTrustedRootCert()
		assert.Nil(t, err)
		assert.NotEmpty(t, handle)
	})

	t.Run("returns error when server returns non-200 status code", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})

		localConf := setup(t, handler)
		_, err := localConf.AddTrustedRootCert()
		assert.NotNil(t, err)
	})
}

func TestAddClientCert(t *testing.T) {
	t.Run("returns handle when adding cert is successful", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, err := w.Write([]byte(clientCertXMLResponse))
			assert.Nil(t, err)
		})

		localConf := setup(t, handler)
		handle, err := localConf.AddClientCert()
		assert.Nil(t, err)
		assert.NotEmpty(t, handle)
	})

	t.Run("returns error when server returns non-200 status code", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})

		localConf := setup(t, handler)
		_, err := localConf.AddClientCert()
		assert.NotNil(t, err)
	})
}

func TestAddPrivateKey(t *testing.T) {
	t.Run("returns handle when adding cert is successful", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			_, err := w.Write([]byte(addKeyXMLResponse))
			assert.Nil(t, err)
		})

		localConf := setup(t, handler)
		handle, err := localConf.AddPrivateKey()
		assert.Nil(t, err)
		assert.NotEmpty(t, handle)
	})

	t.Run("returns error when server returns non-200 status code", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
		})

		localConf := setup(t, handler)
		_, err := localConf.AddPrivateKey()
		assert.NotNil(t, err)
	})
}
func TestCheckReturnValue(t *testing.T) {
	tests := []struct {
		name    string
		in      int
		item    string
		want    bool
		wantErr error
	}{
		{"TestNoError", 0, "item", false, nil},
		{"TestAlreadyExists", common.PT_STATUS_DUPLICATE, "item", true, errors.New("item already exists. You must remove it manually before continuing")},
		{"TestInvalidItem", common.PT_STATUS_INVALID_CERT, "item", true, fmt.Errorf("%s invalid cert", "item")},
		{"TestNonZeroReturnCode", 9999, "item", true, fmt.Errorf("non-zero return code: %d", 9999)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := checkReturnValue(tt.in, tt.item)

			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}

			if (gotErr != nil && tt.wantErr == nil) || (gotErr == nil && tt.wantErr != nil) || (gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error()) {
				t.Errorf("gotErr %v, wantErr %v", gotErr, tt.wantErr)
			}
		})
	}
}
