package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/google/uuid"
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

func generateKeyFileStruct(pass []byte, vanity string, caseSensitive bool, timeout int) (kf *common.Keyfile, err error) {
	kf = &common.Keyfile{}

	kf.Crypto.Kdf = kdf
	kf.Crypto.Cipher = strings.ToLower(encalg)
	xuuid, err := uuid.NewUUID()
	kf.ID = xuuid.String()

	ethkey := make([]byte, 32)
	if len(privhex) > 1 {
		if privhex[:2] == "0x" {
			privhex = privhex[2:]
		}
		var privb []byte
		privb, err = hex.DecodeString(privhex)
		if err != nil {
			return
		}
		if len(privb) > 32 {
			privb = privb[:32]
		}
		copy(ethkey[32-len(privb):], privb) //padding
	} else {
		//Generate the Koblitz private key
		ethkey, err = common.TimeConstraindedVanityKey(vanity, caseSensitive, timeout)
		if err != nil {
			return
		}
	}

	err = common.EncryptAES(kf, ethkey, pass)
	if err != nil {
		return
	}

	pubkeyeth := common.Scalar2Pub(ethkey)
	addr := common.CRCAddressFromPub(pubkeyeth)
	kf.PubKey = hex.EncodeToString(pubkeyeth)
	kf.Address = addr

	return
}

func generateKeyFile(cmd *cobra.Command, args []string) {
	if len(genFilename) == 0 {
		genFilename = time.Now().Format(time.RFC3339) + ".json"
	}

	pass, err := common.SetPassword()
	if err != nil {
		fmt.Println(err)
		return
	}

	kf, err := generateKeyFileStruct(pass, vanity, caseSensitive, timeout)
	if err != nil {
		fmt.Println(err)
		return
	}
	bytes, err := json.Marshal(kf)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Public key: %s\n", kf.PubKey)
	fmt.Printf("Address: %s\n", kf.Address)
	ioutil.WriteFile(genFilename, bytes, 0644)
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
