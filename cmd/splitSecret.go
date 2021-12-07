package cmd

import (
	"fmt"

	"github.com/proveniencenft/primesecrets/poly"
	"github.com/spf13/cobra"
)

// splitSecretCmd
var splitSecretCmd = &cobra.Command{
	Use:   "splitSecret --fileptrn filename_pattern -n shares -t theshold -s secret",
	Short: "Split a secret t/n (shamir's scheme)",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   splitSecret,
}

func splitSecret(cmd *cobra.Command, args []string) {

}

func split(secret []byte, n, t int) {
	field := poly.SetField(nil)
	fmt.Print(field)
}

var secret, filenamePat string
var nshares, threshold int

func init() {
	rootCmd.AddCommand(splitSecretCmd)

	splitSecretCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	splitSecretCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	splitSecretCmd.Flags().StringVarP(&filenamePat, "fileptrn", "f", "", "--fileptrn filename_Pattern")
	splitSecretCmd.Flags().StringVarP(&secret, "secret", "s", "", "--secret your_secret")
	splitSecretCmd.Flags().IntVarP(&nshares, "nshares", "n", 2, "--nshares number_of_shares")
	splitSecretCmd.Flags().IntVarP(&threshold, "threshold", "t", 2, "--theshold no_of_shares_needed")
}
