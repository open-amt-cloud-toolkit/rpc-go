package configure

import (
	"errors"
	"fmt"
	"rpc/config"
	"rpc/pkg/utils"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type TLSMode string

const (
	TLSModeServer          TLSMode = "Server"
	TLSModeServerAndNonTLS         = "ServerAndNonTLS"
	TLSModeMutual                  = "Mutual"
	TLSModeMutualAndNonTLS         = "MutualAndNonTLS"
)

func TLSModesToString() string {
	return fmt.Sprintf("%s, %s, %s, %s", TLSModeServer, TLSModeServerAndNonTLS, TLSModeMutual, TLSModeMutualAndNonTLS)
}

func ParseTLSMode(s string) (TLSMode, error) {
	switch s {
	case string(TLSModeServer), string(TLSModeServerAndNonTLS), string(TLSModeMutual), string(TLSModeMutualAndNonTLS):
		return TLSMode(s), nil
	default:
		return "", fmt.Errorf("invalid TLS mode: %s", s)
	}
}

func ConfigureTLSCmd(cfg *config.Config) *cobra.Command {
	var configureTLSCmd = &cobra.Command{
		Use:   utils.SubCommandConfigureTLS,
		Short: "Configures TLS in AMT.",
		Example: "rpc configure tls --config config.yaml" +
			"rpc configure tls --mode <Server> --eaaddress <IP Address or FQDN of Enterprise Assistant> --eaUsername <EAUsername> --eaPassword<EAPassword> --amtpassword <AMTPassword>",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTLSConfig(cmd, args, cfg)
		},
	}

	tlsModeUsage := fmt.Sprintf("TLS authentication usage model (%s) (default %s)", TLSModesToString(), cfg.Configure.TLS.Mode)
	configureTLSCmd.Flags().StringVar(&cfg.Configure.TLS.Mode, "mode", string(TLSModeServer), tlsModeUsage)
	configureTLSCmd.Flags().StringVar(&cfg.Configure.TLS.ConfigPathOrString, "config", "", "Path to the configuration file or JSON/YAML string")
	configureTLSCmd.Flags().StringVar(&cfg.Configure.TLS.ConfigJSONString, "configjson", "", "Configuration as a JSON string")
	configureTLSCmd.Flags().StringVar(&cfg.Configure.TLS.ConfigYAMLString, "configyaml", "", "Configuration as a YAML string")
	configureTLSCmd.Flags().IntVar(&cfg.Configure.TLS.Delay, "delay", 3, "Delay time in seconds after putting remote TLS settings") //ToDo: Check if we can remove
	configureTLSCmd.Flags().StringVar(&cfg.Configure.EA.Address, "eaaddress", "", "Enterprise Assistant address")
	configureTLSCmd.Flags().StringVar(&cfg.Configure.EA.Username, "eausername", "", "Enterprise Assistant username")
	configureTLSCmd.Flags().StringVar(&cfg.Configure.EA.Password, "eapassword", "", "Enterprise Assistant password")

	return configureTLSCmd
}

func runTLSConfig(_ *cobra.Command, _ []string, cfg *config.Config) error {
	cfg.Configure.Subcommand = utils.SubCommandConfigureTLS

	if cfg.Configure.TLS.ConfigPathOrString != "" {
		return readConfigFile(cfg.Configure.TLS.ConfigPathOrString, cfg)
	}

	if cfg.Configure.TLS.ConfigJSONString != "" {
		viper.SetConfigType("json")
		return readConfigString(cfg.Configure.TLS.ConfigJSONString, cfg)
	}

	if cfg.Configure.TLS.ConfigYAMLString != "" {
		viper.SetConfigType("yaml")
		return readConfigString(cfg.Configure.TLS.ConfigYAMLString, cfg)
	}
	
	if cfg.Configure.AMTPassword == "" {
		password, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.AMTPassword = password
	}

	return validateConfig(cfg)
}

func readConfigFile(configPathOrString string, config *config.Config) error {
	viper.SetConfigFile(configPathOrString)
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	// acmConfig := viper.Sub("acmactivate")
	// if acmConfig == nil {
	// 	return errors.New("acmactivate settings not found in config")
	// }
	if err := viper.Unmarshal(config); err != nil {
		return err
	}
	return validateConfig(config)
}

func readConfigString(configString string, config *config.Config) error {
	if err := viper.ReadConfig(strings.NewReader(configString)); err != nil {
		return err
	}

	// acmConfig := viper.Sub("acmactivate")
	// if acmConfig != nil {
	// 	if err := acmConfig.Unmarshal(config); err != nil {
	// 		return err
	// 	}
	// }

	if err := viper.Unmarshal(config); err != nil {
		return err
	}

	return validateConfig(config)
}

func validateConfig(cfg *config.Config) error {
	missingFields := []string{}
	if cfg.Configure.TLS.Mode == "" {
		missingFields = append(missingFields, "--mode")
	}

	// Check for Enterprise Assistant credentials
	eaFields := []string{}
	if cfg.Configure.EA.Address == "" {
		eaFields = append(eaFields, "--eaAddress")
	}
	if cfg.Configure.EA.Username == "" {
		eaFields = append(eaFields, "--eaUsername")
	}
	if cfg.Configure.EA.Password == "" {
		eaFields = append(eaFields, "--eaPassword")
	}

	// If any of the EA fields are provided, ensure all are provided
	if len(eaFields) > 0 && len(eaFields) < 3 {
		missingEAFieldsStr := strings.Join(eaFields, ", ")
		errMsg := fmt.Sprintf("If any Enterprise Assistant settings are provided, all must be included: %s", missingEAFieldsStr)
		missingFields = append(missingFields, errMsg)
	}

	if len(missingFields) > 0 {
		missingFieldsStr := strings.Join(missingFields, ", ")
		errMsg := fmt.Sprintf("Missing required flags for TLS: %s. Alternatively, provide a configuration using --config, --configjson, or --configyaml", missingFieldsStr)
		log.Error(errMsg)
		return errors.New(errMsg)
	}

	return nil
}
