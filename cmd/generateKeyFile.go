package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/btcsuite/btcd/btcec"
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

func generateKeyFile(cmd *cobra.Command, args []string) {
	if len(genFilename) == 0 {
		genFilename = time.Now().Format(time.RFC3339) + ".json"
	}

	kf := common.Keyfile{}

	kf.Crypto.Kdf = kdf

	pass, err := common.SetPassword()
	if err != nil {
		fmt.Println(err)
		return
	}

	ethkey := make([]byte, 32)
	if len(privhex) > 1 {
		if privhex[:2] == "0x" {
			privhex = privhex[2:]
		}
		privb, err := hex.DecodeString(privhex)
		if err != nil {
			fmt.Println("Bad key:", err)
		}
		if len(privb) > 32 {
			privb = privb[:32]
		}
		copy(ethkey[32-len(privb):], privb)
	} else {
		//Generate the Koblitz private key
		rand.Read(ethkey)
	}

	salt := make([]byte, 16)
	rand.Read(salt)
	/*
		kf.Crypto.KdfparamsPack.Dklen=32
		kf.Crypto.KdfparamsPack.N=131072
		kf.Crypto.KdfparamsPack.P=1
		kf.Crypto.KdfparamsPack.R=8
		kf.Crypto.KdfparamsPack.Salt=hex.EncodeToString(salt)
	*/
	switch kdf {
	case "scrypt":
		kf.Crypto.KdfScryptParams.Dklen = 32
		kf.Crypto.KdfScryptParams.N = 131072
		kf.Crypto.KdfScryptParams.P = 1
		kf.Crypto.KdfScryptParams.R = 8
		kf.Crypto.KdfScryptParams.Salt = hex.EncodeToString(salt)
	default:
		fmt.Println("Unsupported KDF scheme")
		return
	}

	err = common.EncryptAES128(&kf, ethkey, pass)
	if err != nil {
		fmt.Println(err)
		return
	}

	x, y := btcec.S256().ScalarBaseMult(ethkey)
	pubkeyeth := append(x.Bytes(), y.Bytes()...)
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubkeyeth))
	kecc := common.Keccak256(pubkeyeth)
	addr := kecc[12:]

	kf.Address = hex.EncodeToString(addr)

	bytes, err := json.Marshal(&kf)
	if err != nil {
		fmt.Println(err)
		return
	}
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
	generateKeyFileCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	generateKeyFileCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")
	generateKeyFileCmd.Flags().StringVar(&privhex, "priv", "", "--priv private_key_in_hex")
}
