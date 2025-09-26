package cmd

import (
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

// readKeyFileCmd represents the readKeyFile command
func newReadKeyFileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "readKeyFile filename [-v]",
		Short: "Read an Ethereum key file",
		Long:  `Read an Ethereum key file. In verbose mode, reveals the secret`,
		Run:   readKeyFileCobraWrapper,
	}
}

func readKeyFileCobraWrapper(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Println("missing or ambiguous filename")
		return
	}
	var err error
	kf, err := common.ReadAndProcessKeyfile(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	kf.DisplayKeyFile(common.Verbose)

	return
}

func init() {
	rcfc := newReadKeyFileCmd()
	rootCmd.AddCommand(rcfc)

	rcfc.Flags().BoolVarP(&common.Verbose, "verbose", "v", false, "Verbose output")
}
