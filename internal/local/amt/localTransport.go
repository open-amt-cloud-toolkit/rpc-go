package bacon

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"rpc/internal/lm"

	"github.com/sirupsen/logrus"
)

// LocalTransport - Your custom net.Conn implementation
type LocalTransport struct {
	local  lm.LocalMananger
	data   chan []byte
	errors chan error
	status chan bool
}

func NewLocalTransport() *LocalTransport {
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)
	lmStatus := make(chan bool)
	lm := &LocalTransport{
		local:  lm.NewLMEConnection(lmDataChannel, lmErrorChannel, lmStatus),
		data:   lmDataChannel,
		errors: lmErrorChannel,
		status: lmStatus,
	}
	// defer lm.local.Close()
	// defer close(lmDataChannel)
	// defer close(lmErrorChannel)
	// defer close(lmStatus)

	err := lm.local.Initialize()
	if err != nil {
		logrus.Error(err)
	}

	return lm
}

// Custom dialer function
func (l *LocalTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	//Something comes here...Maybe
	logrus.Info("FUCK YEAH")
	go l.local.Listen()

	// send channel open
	err := l.local.Connect()

	if err != nil {
		logrus.Error(err)
		return nil, err
	}
	// wait for channel open confirmation
	<-l.status
	logrus.Trace("Channel open confirmation received")

	// Serialize the HTTP request to raw form
	rawRequest, err := serializeHTTPRequest(r)
	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	var responseReader *bufio.Reader
	// send our data to LMX
	err = l.local.Send(rawRequest)
	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	for dataFromLM := range l.data {
		if len(dataFromLM) > 0 {
			logrus.Debug("received data from LME")
			logrus.Trace(string(dataFromLM))

			// /<-l.status
			responseReader = bufio.NewReader(bytes.NewReader(dataFromLM))
			break
		}
	}

	response, err := http.ReadResponse(responseReader, r)
	if err != nil {
		logrus.Error("Failed to parse response: ", err)
		return nil, err
	}

	return response, nil
}

func serializeHTTPRequest(r *http.Request) ([]byte, error) {
	var reqBuffer bytes.Buffer

	// Write request line
	reqLine := fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	reqBuffer.WriteString(reqLine)

	// Write headers
	r.Header.Write(&reqBuffer)
	reqBuffer.WriteString("\r\n") // End of headers

	// Write body if present
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		// Important: Replace the body so it can be read again later if needed
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		reqBuffer.Write(bodyBytes)
	}

	return reqBuffer.Bytes(), nil
}
