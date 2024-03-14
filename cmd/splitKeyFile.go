package cmd

import (
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

// splitStringCmd
var splitKeyFileCmd = &cobra.Command{
	Use:   "splitKeyFile --in file_to_split --fileptrn filename_pattern -n shares -t theshold",
	Short: "Split a secret t/n (shamir's scheme)",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   splitKeyFileWrapper,
}

func splitKeyFileWrapper(cmd *cobra.Command, args []string) {
	kf, err := common.ReadAndProcessKeyfile(infile)
	if err != nil {
		fmt.Println("Error parsing keyfile:", err)
		return
	}
	splitBytesToFiles(kf.Plaintext, filenamePat4KeyFile, numshares, threshold)
}

var filenamePat4KeyFile string

func init() {
	rootCmd.AddCommand(splitKeyFileCmd)

	splitKeyFileCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	splitKeyFileCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	splitKeyFileCmd.Flags().StringVarP(&filenamePat4KeyFile, "fileptrn", "f", "splitKeyFile", "--fileptrn filename_Pattern")
	splitKeyFileCmd.Flags().StringVar(&infile, "in", "", "--in filename")
	splitKeyFileCmd.Flags().IntVarP(&numshares, "nshares", "n", 2, "--nshares number_of_shares")
	splitKeyFileCmd.Flags().IntVarP(&threshold, "threshold", "t", 2, "--theshold no_of_shares_needed")
	splitKeyFileCmd.MarkFlagRequired("in")

}
