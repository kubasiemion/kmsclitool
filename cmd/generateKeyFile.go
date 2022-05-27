package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1"
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

func generateKeyFileStruct(pass []byte) (kf *common.Keyfile, err error) {
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
		rand.Read(ethkey)
	}

	err = common.EncryptAES(kf, ethkey, pass)
	if err != nil {
		return
	}

	x, y := secp256k1.S256().ScalarBaseMult(ethkey)
	pubkeyeth := append(x.Bytes(), y.Bytes()...)
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubkeyeth))
	kecc := common.Keccak256(pubkeyeth)
	addr := kecc[12:]

	kf.Address = common.CRCAddressString(addr)

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

	kf, err := generateKeyFileStruct(pass)
	if err != nil {
		fmt.Println(err)
		return
	}
	bytes, err := json.Marshal(kf)
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
	generateKeyFileCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	generateKeyFileCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	generateKeyFileCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")
	generateKeyFileCmd.Flags().StringVar(&privhex, "priv", "", "--priv private_key_in_hex")
}
