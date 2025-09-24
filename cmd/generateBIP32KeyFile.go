package cmd

import (
	"fmt"
	"strings"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip32"
)

// generateBIP32KeyFileCmd represents the generateKeyFile command
var generateBIP32KeyFileCmd = &cobra.Command{
	Use:   "generateBIP32KeyFile [--f filename][--mnemonic mnemonic]",
	Short: "Generate a new keyfile with a BIP32 key",
	Long:  `Generates a new keyfile with a BIP32 key. Interactively asks for password (do not forget your choice!).`,
	Run:   generateBIP32KeyFile,
}

func generateBIP32KeyFile(cmd *cobra.Command, args []string) {
	var err error
	var addr string
	var key *bip32.Key
	if len(privhex) > 1 {

		key, err = bip32.B58Deserialize(bip32in58)

	} else {
		//Generate the BIP private key
		seed, err := bip32.NewSeed()
		if err != nil {

		}
		key, err = bip32.NewMasterKey(seed)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	uid := common.NewUuid()
	keyser, err := key.Serialize()
	addr = common.CRCAddressFromPub(common.Scalar2Pub(key.Key))
	if err != nil {

	}
	addr = common.CRCAddressFromPub(common.Scalar2Pub(key.Key))
	if split {
		genFilename, _ = strings.CutSuffix(genFilename, ".json")

		common.SplitBytesToFiles(keyser, genFilename, numshares, threshold, encalg, kdf,
			"File contains a shard of a key for "+addr)
	} else {
		kf, err := common.WrapSecret(genFilename, uid.GetWithPattern(common.BIP32), keyser, encalg, kdf, addr, 0)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = common.WriteKeyfile(kf, "")
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Keyfile written to %s\n", kf.Filename)
	}

}

var bip32in58 string

func init() {
	rootCmd.AddCommand(generateBIP32KeyFileCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateBIP32KeyFileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateBIP32KeyFileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	generateBIP32KeyFileCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	generateBIP32KeyFileCmd.Flags().StringVar(&kdf, "kdf", "pbkdf2", "--kdf preferredKDF")
	generateBIP32KeyFileCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")
	generateBIP32KeyFileCmd.Flags().StringVar(&bip32in58, "priv", "", "--priv private_key_in_base58")
	generateBIP32KeyFileCmd.Flags().StringVar(&vanity, "vanity", "", "--vanity vanity_address_regexp")
	generateBIP32KeyFileCmd.Flags().BoolVar(&caseSensitive, "vanityCaseSensitive", false, "--vanityCaseSensitive=bool")
	generateBIP32KeyFileCmd.Flags().IntVarP(&timeout, "timeout", "t", 180, "--timeout generation-time-limit-in-seconds")
	generateBIP32KeyFileCmd.Flags().BoolVar(&split, "split", false, "--split should the result be split across multiple files")
	generateBIP32KeyFileCmd.Flags().IntVar(&numshares, "numshares", 2, "--nshares number_of_shares")
	generateBIP32KeyFileCmd.Flags().IntVar(&threshold, "thresh", 2, "--theshold no_of_shares_needed")
}
