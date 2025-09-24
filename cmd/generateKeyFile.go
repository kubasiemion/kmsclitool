package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

// generateKeyFileCmd represents the generateKeyFile command
var generateKeyFileCmd = &cobra.Command{
	Use:   "generateKeyFile [--f filename]",
	Short: "Generate a new keyfile",
	Long:  `Generates a new keyfile. Interactively asks for password (do not forget your choice!).`,
	Run:   generateKeyFile,
}

var genFilename string
var kdf string
var kdfiter int
var encalg string

func generateKeyFile(cmd *cobra.Command, args []string) {
	var tries int
	var timespan time.Duration
	var err error
	var addr string
	ethkey := make([]byte, 32)
	if len(privhex) > 1 {

		ethkey = common.Pad(privhex, 32)

	} else {
		//Generate the Koblitz private key
		ethkey, addr, tries, timespan, err = common.TimeConstraindedVanityKey(vanity, caseSensitive, timeout)
		if err != nil {
			return
		}
		if len(vanity) > 0 {
			fmt.Printf("Vanity address %s found in %v tries within %v \n", addr, tries, timespan)
		}
	}
	uid := common.NewUuid()
	addrTxt := common.CRCAddressFromPub(common.Scalar2Pub(ethkey))
	if split {
		genFilename, _ = strings.CutSuffix(genFilename, ".json")
		common.SplitBytesToFiles(ethkey, genFilename, numshares, threshold, encalg, kdf,
			"File contains a shard of a key for "+addrTxt)
	} else {
		kf, err := common.WrapSecret(genFilename, uid.String(), ethkey, encalg, kdf, addrTxt, kdfiter)
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

func init() {
	rootCmd.AddCommand(generateKeyFileCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateKeyFileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateKeyFileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	generateKeyFileCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	generateKeyFileCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	generateKeyFileCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")
	generateKeyFileCmd.Flags().BytesHexVar(&privhex, "priv", nil, "--priv private_key_in_hex")
	generateKeyFileCmd.Flags().StringVar(&vanity, "vanity", "", "--vanity vanity_address_regexp")
	generateKeyFileCmd.Flags().BoolVar(&caseSensitive, "vanityCaseSensitive", false, "--vanityCaseSensitive=bool")
	generateKeyFileCmd.Flags().IntVarP(&timeout, "timeout", "t", 180, "--timeout generation-time-limit-in-seconds")
	generateKeyFileCmd.Flags().BoolVar(&split, "split", false, "--split should the result be split across multiple files")
	generateKeyFileCmd.Flags().IntVar(&numshares, "numshares", 2, "--nshares number_of_shares")
	generateKeyFileCmd.Flags().IntVar(&threshold, "thresh", 2, "--theshold no_of_shares_needed")
	generateKeyFileCmd.Flags().IntVarP(&kdfiter, "kdfiter", "N", 0, "-n/--kdfiter number_of_kdf_iterations")
}

var split bool

var vanity = ""
var caseSensitive bool
var timeout = 180
