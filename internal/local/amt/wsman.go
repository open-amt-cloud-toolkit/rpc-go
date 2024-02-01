package bacon

import (
	"encoding/base64"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/hostbasedsetup"
)

type WSMANer interface {
	SetupWsmanClient(username string, password string)
	Unprovision(int) (setupandconfiguration.Response, error)
	GetGeneralSettings() (general.Response, error)
	HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error)
	GetHostBasedSetupService() (hostbasedsetup.Response, error)
	AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error)
	HostBasedSetupServiceAdmin(password string, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error)
}

type GoWSMANMessages struct {
	wsmanMessages wsman.Messages
	target        string
}

func NewGoWSMANMessages(lmsAddress string) *GoWSMANMessages {
	return &GoWSMANMessages{
		target: lmsAddress,
	}
}

func (g *GoWSMANMessages) SetupWsmanClient(username string, password string) {

	clientParams := wsman.ClientParameters{
		Target:    g.target,
		Username:  username,
		Password:  password,
		UseDigest: true,
		UseTLS:    false,
	}

	wsmanClient := client.NewWsman(clientParams.Target, clientParams.Username, clientParams.Password, clientParams.UseDigest, clientParams.UseTLS, clientParams.SelfSignedAllowed)
	lt := NewLocalTransport()
	wsmanClient.Transport = lt

	g.wsmanMessages = wsman.NewMessages(clientParams)
	// } else {
	// 	wsmanClient := NewLocalWsman("", "")
	// 	g.wsmanMessages = wsman.NewMessages(wsmanClient)
	// }
}

func (g *GoWSMANMessages) GetGeneralSettings() (general.Response, error) {
	return g.wsmanMessages.AMT.GeneralSettings.Get()
}

func (g *GoWSMANMessages) HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.Setup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password)
}

func (g *GoWSMANMessages) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.Get()
}

func (g *GoWSMANMessages) AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.AddNextCertInChain(cert, isLeaf, isRoot)
}

func (g *GoWSMANMessages) HostBasedSetupServiceAdmin(password, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.AdminSetup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password, base64.StdEncoding.EncodeToString(nonce), hostbasedsetup.SigningAlgorithmRSASHA2256, signature)
}

func (g *GoWSMANMessages) Unprovision(int) (setupandconfiguration.Response, error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.Unprovision(1)
}
