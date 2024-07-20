package configure

import (
	"rpc/config"
	"rpc/pkg/utils"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var validFeatures = []string{
	"kvm",
	"sol",
	"ider",
}

func AMTFeaturesCmd(cfg *config.Config) *cobra.Command {
	var amtFeaturesCmd = &cobra.Command{
		Use:     utils.SubCommandSetAMTFeatures,
		Short:   "Manage AMT features like KVM, SOL, and IDER, and set user consent options.",
		Example: "rpc.exe configure amtfeatures kvm sol ider --userconsent none",
		Long: "This command allows you to enable or disable AMT features such as KVM, SOL, and IDER. " +
			"You can also set user consent options (kvm, all, or none). " +
			"At least one feature must be specified. Specified features will be enabled; " +
			"unspecified features will be disabled.",
		Args: cobra.RangeArgs(1, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAMTFeaturesConfig(cmd, args, cfg)
		},
	}

	amtFeaturesCmd.Flags().StringVar(&cfg.Configure.AMTFeatures.UserConsent, "userconsent", "", "Sets user consent (ACM only): kvm, all, none")

	return amtFeaturesCmd

}

func runAMTFeaturesConfig(_ *cobra.Command, args []string, cfg *config.Config) error {
	// Process flags to enable/disable features
	for _, arg := range args {
		switch arg {
		case "kvm":
			cfg.Configure.AMTFeatures.KVM = true
		case "sol":
			cfg.Configure.AMTFeatures.SOL = true
		case "ider":
			cfg.Configure.AMTFeatures.IDER = true
		}
	}

	// Validate UserConsent
	if cfg.Configure.AMTFeatures.UserConsent != "" {
		cfg.Configure.AMTFeatures.UserConsent = strings.ToLower(cfg.Configure.AMTFeatures.UserConsent)
		switch cfg.Configure.AMTFeatures.UserConsent {
		case "kvm", "all", "none":
			// Valid userConsent value
		default:
			log.Error("invalid value for user consent:", cfg.Configure.AMTFeatures.UserConsent)
			return utils.IncorrectCommandLineParameters
		}
	}

	// If password is missing, prompt the user to enter it
	if cfg.Configure.AMTPassword == "" {
		password, err := PromptForPassword()
		if err != nil {
			return err
		}
		cfg.Configure.AMTPassword = password
	}

	cfg.Configure.Subcommand = utils.SubCommandSetAMTFeatures

	return nil
}
