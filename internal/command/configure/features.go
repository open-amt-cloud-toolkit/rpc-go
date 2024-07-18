package configure

import (
	"os"
	"rpc/config"
	"rpc/pkg/utils"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var validFeatures = []string{
	"kvm",
	"sol",
	"ider",
}

func AMTFeaturesCmd(cfg *config.Config) *cobra.Command {
	var amtFeaturesCmd = &cobra.Command{
		Use:   utils.SubCommandSetAMTFeatures,
		Short: "Manage AMT features like KVM, SOL, and IDER, and set user consent options.",
// 		Long: `This command allows you to enable or disable AMT features such as KVM, SOL, and IDER. 
// You can also set user consent options (kvm, all, or none). 
// At least one feature must be specified. Specified features will be enabled; unspecified features will be disabled.`,
		Args: cobra.RangeArgs(1, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAMTFeaturesConfig(cmd, args, cfg)
		},
	}

	amtFeaturesCmd.Flags().StringVar(&cfg.AMTConfiguration.AMTFeatures.UserConsent, "userConsent", "", "Sets user consent (ACM only): kvm, all, none")
	amtFeaturesCmd.Flags().BoolVar(&cfg.AMTConfiguration.AMTFeatures.KVM, "kvm", false, "Enable or Disable KVM (Keyboard, Video, Mouse)")
	amtFeaturesCmd.Flags().BoolVar(&cfg.AMTConfiguration.AMTFeatures.SOL, "sol", false, "Enable or Disable SOL (Serial Over LAN)")
	amtFeaturesCmd.Flags().BoolVar(&cfg.AMTConfiguration.AMTFeatures.IDER, "ider", false, "Enable or Disable IDER (IDE Redirection)")


	return amtFeaturesCmd

}

func runAMTFeaturesConfig(_ *cobra.Command, args []string, cfg *config.Config) error {
	// Process flags to enable/disable features
	for _, arg := range args {
		switch arg {
		case "kvm":
			cfg.AMTConfiguration.AMTFeatures.KVM = true
		case "sol":
			cfg.AMTConfiguration.AMTFeatures.SOL = true
		case "ider":
			cfg.AMTConfiguration.AMTFeatures.IDER = true
		}
	}

	// Validate UserConsent
	if cfg.AMTConfiguration.AMTFeatures.UserConsent != "" {
		cfg.AMTConfiguration.AMTFeatures.UserConsent = strings.ToLower(cfg.AMTConfiguration.AMTFeatures.UserConsent)
		switch cfg.AMTConfiguration.AMTFeatures.UserConsent {
		case "kvm", "all", "none":
			// Valid userConsent value
		default:
			log.Error("invalid value for user consent:", cfg.AMTConfiguration.AMTFeatures.UserConsent)
			return utils.IncorrectCommandLineParameters
		}
	}

	// If password is missing, prompt the user to enter it
	if cfg.AMTConfiguration.AMTPassword == "" {
		log.Infoln("Please enter AMT Password: ")
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Infoln("Error reading password:", err)
			return utils.MissingOrIncorrectPassword
		}
		cfg.AMTConfiguration.AMTPassword = string(bytePassword)
		if cfg.AMTConfiguration.AMTPassword == "" {
			log.Error("Missing or incorrect password")
			return utils.MissingOrIncorrectPassword
		}
	}

	cfg.IsLocal = true

	return nil
}
