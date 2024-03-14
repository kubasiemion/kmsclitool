package cmd

import (
	"fmt"

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
var encalg string

func generateKeyFile(cmd *cobra.Command, args []string) {

	pass, err := common.SetPassword("Password for the keyfile:")
	if err != nil {
		fmt.Println(err)
		return
	}

	kf, err, tries, span := common.GenerateAndWrapNewKey(pass, kdf, encalg, privhex, vanity, caseSensitive, timeout)
	if err != nil {
		fmt.Println(err)
		return
	}

	kf.Hint, err = common.GetPasswordHint()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Public key: %s\n", kf.PubKey)
	fmt.Printf("Address: %s\n", kf.Address)
	common.WriteKeyfile(kf, genFilename)
	fmt.Printf("Written to the file: '%s'\n", kf.Filename)
	if len(vanity) > 0 {
		fmt.Printf("Generated in %v tries within %v \n", tries, span)
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
	generateKeyFileCmd.Flags().StringVar(&kdf, "kdf", "pbkdf2", "--kdf preferredKDF")
	generateKeyFileCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")
	generateKeyFileCmd.Flags().BytesHexVar(&privhex, "priv", nil, "--priv private_key_in_hex")
	generateKeyFileCmd.Flags().StringVar(&vanity, "vanity", "", "--vanity vanity_address_regexp")
	generateKeyFileCmd.Flags().BoolVar(&caseSensitive, "vanityCaseSensitive", false, "--vanityCaseSensitive=bool")
	generateKeyFileCmd.Flags().IntVarP(&timeout, "timeout", "t", 180, "--timeout generation-time-limit-in-seconds")
	generateKeyFileCmd.Flags().BoolVar(&split, "split", false, "--split should the result be split across multiple files")
	generateKeyFileCmd.Flags().IntVar(&numshares, "numshares", 2, "--nshares number_of_shares")
	generateKeyFileCmd.Flags().IntVar(&threshold, "thresh", 2, "--theshold no_of_shares_needed")
}

var split bool

var vanity = ""
var caseSensitive bool
var timeout = 180
