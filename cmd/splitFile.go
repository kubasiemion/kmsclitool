package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const splitFileLabel = "File contains a shard of a secret file"

// splitStringCmd
var splitFileCmd = &cobra.Command{
	Use:   "splitFile --in file_to_split --fileptrn filename_pattern -n shares -t theshold",
	Short: "Split a file t/n (shamir's scheme)",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   splitFileWrapper,
}

func splitFileWrapper(cmd *cobra.Command, args []string) {
	bt, err := os.ReadFile(infile)
	if err != nil {
		fmt.Println(err)
		return
	}
	splitBytesToFiles(bt, filenamePat4File, numshares, threshold)
}

var infile string

func init() {
	rootCmd.AddCommand(splitFileCmd)

	splitFileCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	splitFileCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	splitFileCmd.Flags().StringVarP(&filenamePat4File, "fileptrn", "f", "splitFile", "--fileptrn filename_Pattern")
	splitFileCmd.Flags().StringVar(&infile, "in", "", "--in filename")
	splitFileCmd.Flags().IntVarP(&numshares, "nshares", "n", 2, "--nshares number_of_shares")
	splitFileCmd.Flags().IntVarP(&threshold, "threshold", "t", 2, "--theshold no_of_shares_needed")
	splitFileCmd.MarkFlagRequired("in")

}
