package activate

import (
	"github.com/spf13/cobra"
)

type activationFlags struct {
	url                string
	profile            string
	uuid               string
	name               string
	dns                string
	hostname           string
	ccmMode            bool
	acmMode            bool
	configPathOrString string
	configJSONString   string
	configYAMLString   string
	amtPassword        string
	provisioningCert   string
	provisioningCertPwd string
	nocertverification bool
}

var ActivateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Activate AMT device",
}