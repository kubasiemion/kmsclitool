package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
var encalg string

func generateKeyFile(cmd *cobra.Command, args []string) {
	if len(genFilename) == 0 {
		genFilename = time.Now().Format(time.RFC3339) + ".json"
	}

	pass, err := common.SetPassword()
	if err != nil {
		fmt.Println(err)
		return
	}

	kf, err, tries, span := common.GenerateKeyFileStruct(pass, kdf, encalg, privhex, vanity, caseSensitive, timeout)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(kf)
	bytes, err := json.Marshal(kf)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Public key: %s\n", kf.PubKey)
	fmt.Printf("Address: %s\n", kf.Address)
	ioutil.WriteFile(genFilename, bytes, 0644)
	fmt.Printf("Written to the file: '%s'\n", genFilename)
	fmt.Printf("Generated in %v tries within %v \n", tries, span)
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
	generateKeyFileCmd.Flags().StringVar(&privhex, "priv", "", "--priv private_key_in_hex")
	generateKeyFileCmd.Flags().StringVar(&vanity, "vanity", "", "--vanity vanity_address_regexp")
	generateKeyFileCmd.Flags().BoolVar(&caseSensitive, "vanityCaseSensitive", false, "--vanityCaseSensitive=bool")
	generateKeyFileCmd.Flags().IntVarP(&timeout, "timeout", "t", 180, "--timeout generation-time-limit-in-seconds")
}

var vanity = ""
var caseSensitive bool
var timeout = 180
