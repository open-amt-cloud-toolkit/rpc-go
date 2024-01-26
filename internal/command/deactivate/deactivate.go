package deactivate

import (
	"github.com/spf13/cobra"
)

var DeactivateCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Deactivate AMT device in CCM/ACM",
}
