package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ACMSettings struct {
	AMTPassword         string `json:"amtPassword" yaml:"amtPassword"`
	ProvisioningCert    string `json:"provisioningCert" yaml:"provisioningCert"`
	ProvisioningCertPwd string `json:"provisioningCertPwd" yaml:"provisioningCertPwd"`
}

var (
	settings ACMSettings
)

func createActivateCommand() *cobra.Command {
	activateCmd := &cobra.Command{
		Use:   "activate",
		Short: "Activate AMT device",
	}

	// Create subcommands for different activation modes
	remoteCmd := &cobra.Command{
		Use:   "remote",
		Short: "Activate remotely using Remote Provisioning Server (RPS)",
		RunE:  runRemoteActivate,
	}

	localCmd := &cobra.Command{
		Use:   "local",
		Short: "Activate locally using Remote Provisioning Client (RPC)",
		RunE:  runLocalActivate,
	}

	// Add flags specific to each subcommand
	remoteCmd.Flags().StringP("url", "u", "", "Websocket address of server to activate against")
	remoteCmd.Flags().StringP("profile", "p", "", "Name of the profile to use")
	remoteCmd.Flags().BoolP("nocertverification", "n", false, "Disable certificate verification")
	remoteCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	localCmd.Flags().BoolP("ccm", "", false, "Activate in CCM mode")
	localCmd.Flags().BoolP("acm", "", false, "Activate in ACM mode")
	localCmd.Flags().StringP("config", "", "", "Path to the configuration file or JSON/YAML string (required for ACM mode if no -amtPassword and -provisioningCert and -provisioningCertPwd are provided)")
	localCmd.Flags().StringP("amtPassword", "", "", "AMT Password (required for CCM and ACM mode or if no -config is provided)")
	localCmd.Flags().StringP("provisioningCert", "", "", "Provisioning Certificate (required for ACM mode or if no -config is provided)")
	localCmd.Flags().StringP("provisioningCertPwd", "", "", "Provisioning Certificate Password (required for CCM mode or if no -config is provided)")
	localCmd.Flags().BoolP("nocertverification", "n", false, "Disable certificate verification")
	localCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	// Mark flags as mandatory for specific subcommands
	remoteCmd.MarkFlagRequired("url")
	remoteCmd.MarkFlagRequired("profile")

	// Add the subcommands to the main activate command
	activateCmd.AddCommand(remoteCmd, localCmd)

	return activateCmd
}

func runRemoteActivate(cmd *cobra.Command, args []string) error {
	// Handle remote activation logic here
	url, _ := cmd.Flags().GetString("url")
	profile, _ := cmd.Flags().GetString("profile")
	nocertverification, _ := cmd.Flags().GetBool("nocertverification")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Printf("Remote Activation: URL=%s, Profile=%s, NoCertVerification=%v, Verbose=%v\n", url, profile, nocertverification, verbose)

	return nil
}

func runLocalActivate(cmd *cobra.Command, args []string) error {
	ccmMode, _ := cmd.Flags().GetBool("ccm")
	acmMode, _ := cmd.Flags().GetBool("acm")
	configPathOrString, _ := cmd.Flags().GetString("config")
	amtPassword, _ := cmd.Flags().GetString("amtPassword")
	provisioningCert, _ := cmd.Flags().GetString("provisioningCert")
	provisioningCertPwd, _ := cmd.Flags().GetString("provisioningCertPwd")
	nocertverification, _ := cmd.Flags().GetBool("nocertverification")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if ccmMode && acmMode {
		return errors.New("You cannot activate in both CCM and ACM modes simultaneously.")
	}

	if !ccmMode && !acmMode {
		return errors.New("Please specify a mode for activation (either --ccm or --acm).")
	}

	// Handle CCM mode activation
	if ccmMode {
		if amtPassword == "" {
			return errors.New("For CCM activation, -amtPassword is required.")
		}
		fmt.Printf("Local Activation: ccmMode=%v, amtPassword=%s, NoCertVerification=%v, Verbose=%v\n", ccmMode, amtPassword, nocertverification, verbose)
		// Handle CCM activation logic here
	}

	// Handle ACM mode activation
	if acmMode {
		if configPathOrString == "" {
			if amtPassword == "" || provisioningCert == "" || provisioningCertPwd == "" {
				return errors.New("For ACM activation, either provide -config or specify -amtPassword, -provisioningCert, and -provisioningCertPwd.")
			}
		} else {
			if amtPassword != "" || provisioningCert != "" || provisioningCertPwd != "" {
				return errors.New("For ACM activation, provide either -config or -amtPassword, -provisioningCert, and -provisioningCertPwd, not both.")
			}
		}

		if configPathOrString != "" {
			if err := readConfig(configPathOrString); err != nil {
				return fmt.Errorf("Error reading configuration: %s", err)
			}

			if err := validateConfig(); err != nil {
				return errors.New(err.Error())
			}
		}

		fmt.Printf("Local Activation: acmMode=%v, amtPassword=%s, NoCertVerification=%v, Verbose=%v\n", acmMode, amtPassword, nocertverification, verbose)
	}

	// Handle common activation logic, including the verbose and certificate verification flags

	return nil
}

func readActivateJSONConfig(jsonString string) error {
	viper.SetConfigType("json")
	if err := viper.ReadConfig(strings.NewReader(jsonString)); err != nil {
		return err
	}
	return viper.Unmarshal(&settings)
}

func readActivateYAMLConfig(yamlString string) error {
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(strings.NewReader(yamlString)); err != nil {
		return err
	}
	return viper.Unmarshal(&settings)
}

func readConfig(configPathOrString string) error {
	if strings.HasSuffix(configPathOrString, ".json") || strings.HasSuffix(configPathOrString, ".yaml") {
		viper.SetConfigFile(configPathOrString)
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
		return viper.UnmarshalKey("acmactivate", &settings)
	} else if strings.HasPrefix(configPathOrString, "{") || strings.HasPrefix(configPathOrString, "[") {
		return readActivateJSONConfig(configPathOrString)
	} else if strings.HasPrefix(configPathOrString, "amtPassword:") || strings.HasPrefix(configPathOrString, "provisioningCert:") {
		return readActivateYAMLConfig(configPathOrString)
	}
	return errors.New("Invalid configuration format or file extension")
}

func validateConfig() error {
	if settings.AMTPassword == "" || settings.ProvisioningCert == "" || settings.ProvisioningCertPwd == "" {
		return errors.New("One or more required configurations are missing")
	}
	return nil
}
