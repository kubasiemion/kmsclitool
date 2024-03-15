package cmd

import (
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/gf256"
	"github.com/spf13/cobra"
)

const splitStringLabel = "File contains a shard of a secret string"

// splitStringCmd
var splitStringCmd = &cobra.Command{
	Use:   "splitString --fileptrn filename_pattern -n shares -t theshold -s secret",
	Short: "Split a secret t/n (shamir's scheme)",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   splitStringWrapper,
}

func splitStringWrapper(cmd *cobra.Command, args []string) {
	common.SplitBytesToFiles([]byte(secret), filenamePat4String, numshares, threshold, encalg, kdf, splitStringLabel)
}

var secret, filenamePat4String string

func init() {
	rootCmd.AddCommand(splitStringCmd)

	splitStringCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	splitStringCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	splitStringCmd.Flags().StringVarP(&filenamePat4String, "fileptrn", "f", "splitSecret", "--fileptrn filename_Pattern")
	splitStringCmd.Flags().StringVarP(&secret, "secret", "s", "", "--secret your_secret")
	splitStringCmd.Flags().IntVarP(&numshares, "nshares", "n", 2, "--nshares number_of_shares")
	splitStringCmd.Flags().IntVarP(&threshold, "threshold", "t", 2, "--theshold no_of_shares_needed")

}

func SplitString(s string, nshares, t int) ([]gf256.Share, error) {

	return gf256.SplitBytes([]byte(s), nshares, t)
}
