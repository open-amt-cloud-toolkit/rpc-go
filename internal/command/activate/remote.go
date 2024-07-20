package activate

import (
	"errors"
	"regexp"
	"rpc/config"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func ActivateRemoteCmd(cfg *config.Config) *cobra.Command {
    
	var activateRemoteCmd = &cobra.Command{
        Use:     "remote",
        Short:   "Activate remotely using Remote Provisioning Server (RPS)",
		Example: "rpc maintenance changepassword -u wss://<RPS server address>/activate --static <new AMT password> --amtPassword <AMT password>",
        RunE:    func(cmd *cobra.Command, args []string) error {
            return runRemoteActivate(cmd, args, cfg)
        },
    }

	// Add flags specific to each activateRemote
	activateRemoteCmd.Flags().StringP("url", "u", "", "Websocket address of server to activate against")
	activateRemoteCmd.Flags().StringP("profile", "p", "", "Name of the profile to use")
	activateRemoteCmd.Flags().BoolP("nocertverification", "n", false, "Disable certificate verification")
	activateRemoteCmd.Flags().String("uuid", "", "override AMT device uuid for use with non-CIRA workflow")
	activateRemoteCmd.Flags().String("name", "", "friendly name to associate with this device")
	activateRemoteCmd.Flags().StringP("dns", "d", "", "dns suffix override")
	activateRemoteCmd.Flags().StringP("hostname", "", "", "hostname override")

	// Mark flags as mandatory
	activateRemoteCmd.MarkFlagRequired("url")
	activateRemoteCmd.MarkFlagRequired("profile")
    return activateRemoteCmd
}

func runRemoteActivate(cmd *cobra.Command, _ []string, cfg *config.Config) error {
	var err error
	cfg.IsLocal = false
	// Map to hold string flags and their associated destinations
	remoteActivationFlags := map[string]*string{
		"url":      &cfg.Activate.URL,
		"profile":  &cfg.Activate.Profile,
		"uuid":     &cfg.Activate.UUID,
		"name":     &cfg.Activate.Name,
		"dns":      &cfg.Activate.DNS,
		"hostname": &cfg.Activate.Hostname,
	}

	// Retrieve string flags
	for flag, dest := range remoteActivationFlags {
		val, err := cmd.Flags().GetString(flag)
		if err != nil {
			return err
		}
		*dest = val
	}

	if cfg.Activate.URL == "" {
		log.Error("-u flag is required and cannot be empty")
		return errors.New("-u flag is required and cannot be empty")
	}

	if cfg.Activate.Profile == "" {
		log.Error("-profile flag is required and cannot be empty")
		return errors.New("-profile flag is required and cannot be empty")
	}

	if cfg.Activate.UUID != "" {
		uuidPattern := regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
		if matched := uuidPattern.MatchString(cfg.Activate.UUID); !matched {
			log.Error("uuid provided does not follow proper uuid format")
			return errors.New("uuid provided does not follow proper uuid format")
		}
		log.Warn("Warning: Overriding UUID prevents device from connecting to MPS")
	}

	cfg.Activate.NoCertverification, err = cmd.Flags().GetBool("nocertverification")
	if err != nil {
		log.WithError(err).Error("Failed to get 'nocertverification' flag")
		return err
	}

	return nil
}
