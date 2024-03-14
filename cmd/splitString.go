package cmd

import (
	"encoding/json"
	"fmt"

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
	splitBytesToFiles([]byte(secret), filenamePat4String, numshares, threshold)
}

func splitBytesToFiles(secret []byte, fpattern string, numshares, threshold int) {

	if len(secret) == 0 {
		fmt.Println("No secret to split")
		return
	}

	shares, err := gf256.SplitBytes(secret, numshares, threshold)
	if err != nil {
		fmt.Println(err)
		return
	}
	secrets := make([][]byte, len(shares))
	for i, sh := range shares {
		secrets[i], err = json.Marshal(sh)
		if err != nil {
			fmt.Println("Error serializing to json:", err)
			return
		}
	}
	uuidbase := common.NewUuid()
	kfs, err := WrapNSecrets(fpattern, uuidbase, secrets, splitStringLabel)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, kf := range kfs {
		err = common.WriteKeyfile(kf, "")
		if err != nil {
			fmt.Println(err)
			return
		}
	}

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
