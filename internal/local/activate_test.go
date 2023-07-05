package local_test

import (
	"fmt"
	"rpc/internal/config"
	"rpc/internal/local"
	"rpc/internal/rps"
	"rpc/pkg/utils"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman"
)

func TestActivationCCM(t *testing.T) {
	localConfig := config.Config{
		Password: "P@ssw0rd",
	}
	// gets required information for us
	rpsPayload := rps.NewPayload()
	lsa, err := rpsPayload.AMT.GetLocalSystemAccount()
	if err != nil {
		fmt.Println(err)
		return
	}
	// payload.Username = lsa.Username
	//localConfig.Password = lsa.Password

	client := wsman.NewClient("http://"+utils.LMSAddress+":"+utils.LMSPort+"/wsman", lsa.Username, lsa.Password, true)
	localConnection := local.NewLocalConfiguration(localConfig, client)
	localConnection.ActivateCCM()
}
