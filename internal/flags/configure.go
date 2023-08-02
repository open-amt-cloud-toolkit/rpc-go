package flags

import (
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
	"rpc/pkg/utils"
)

func (f *Flags) handleConfigureCommand() int {
	f.amtConfigureCommand.StringVar(&f.configContent, "config", "", "specify a config file ")
	if err := f.amtConfigureCommand.Parse(f.commandLineArgs[2:]); err != nil {
		f.amtConfigureCommand.Usage()
		return utils.IncorrectCommandLineParameters
	}
	// runs locally
	f.Local = true
	if f.configContent == "" {
		fmt.Println("-config flag is required and cannot be empty")
		return utils.IncorrectCommandLineParameters
	}
	err := cleanenv.ReadConfig(f.configContent, &f.LocalConfig)
	if err != nil {
		log.Error("config error: ", err)
		return utils.IncorrectCommandLineParameters
	}

	return utils.Success
}
