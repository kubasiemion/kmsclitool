package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/google/uuid"
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/gf256"
	"github.com/proveniencenft/primesecrets/poly"
	"github.com/spf13/cobra"
)

const splitAddress = "File contains a shard of a key"
const splitString = "File contains a shard of a secret string"

// splitSecretCmd
var splitSecretCmd = &cobra.Command{
	Use:   "splitSecret --fileptrn filename_pattern -n shares -t theshold -s secret --iskey=bool",
	Short: "Split a secret t/n (shamir's scheme)",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   splitSecret,
}

func splitSecret(cmd *cobra.Command, args []string) {

	if len(secret) == 0 {
		fmt.Println("No key to split")
		return
	}
	fmt.Println("key:", isSecretAKey)
	if isSecretAKey {
		if secret[:2] == "0x" {
			secret = secret[2:]
		}
		if len(secret) > 64 {
			fmt.Printf("Key too long: (%v bytes)", len(secret))
			return
		}
		key, err := hex.DecodeString(secret)
		if err != nil {
			fmt.Println(err)
			return
		}
		splitKey(key, numshares, threshold)
	} else {
		SplitString(secret, numshares, threshold)
	}

}

func splitKey(key []byte, n, t int) {

	shares, err := poly.SplitBytes(key, n, t, *secp256k1.S256().P)
	if err != nil {
		fmt.Println(err)
		return
	}
	uuidbase, err := uuid.NewUUID()
	if err != nil {
		fmt.Println(err)
		return
	}

	ubytes, err := uuidbase.MarshalBinary()
	fmt.Println(err, ubytes)

	for i, sh := range shares {
		uuidbase[0] = byte(i)
		uid, _ := uuid.FromBytes(uuidbase[:])
		filename := fmt.Sprintf("%s%02x.json", filenamePat, i)
		shenc, err := json.Marshal(sh)
		if err != nil {
			fmt.Println("Error serializing to json:", err)
			return
		}
		writeShareToFile(filename, uid, shenc, splitAddress)
	}

}

func writeShareToFile(filename string, uid uuid.UUID, plaintext []byte, addressText string) error {
	keyf := &common.Keyfile{}
	keyf.Plaintext = plaintext
	keyf.ID = uid.String()
	keyf.Crypto.Cipher = encalg
	keyf.Crypto.Kdf = kdf
	pass, err := common.ReadPassword(fmt.Sprintf("Password for %s:", filename))
	keyf.Address = addressText
	if err != nil {
		return err
	}
	err = common.EncryptAES(keyf, plaintext, pass)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(keyf, " ", " ")
	if err != nil {
		return err
	}
	ioutil.WriteFile(filename, b, 0644)
	return nil
}

var secret, filenamePat string
var numshares, threshold int

func init() {
	rootCmd.AddCommand(splitSecretCmd)

	splitSecretCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	splitSecretCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	splitSecretCmd.Flags().StringVarP(&filenamePat, "fileptrn", "f", "splitkey", "--fileptrn filename_Pattern")
	splitSecretCmd.Flags().StringVarP(&secret, "secret", "s", "", "--secret your_secret")
	splitSecretCmd.Flags().IntVarP(&numshares, "nshares", "n", 2, "--nshares number_of_shares")
	splitSecretCmd.Flags().IntVarP(&threshold, "threshold", "t", 2, "--theshold no_of_shares_needed")
	splitSecretCmd.Flags().BoolVar(&isSecretAKey, "iskey", true, "--iskey false if-splitting-a-string")
}

var isSecretAKey bool

func SplitString(s string, nshares, t int) ([]gf256.Share, error) {
	sh := gf256.Share{}
	sh.Value = []byte{}
	return gf256.SplitBytes([]byte(s), nshares, t)
}

func RecoverString(shares []gf256.Share) (string, error) {
	b, err := gf256.RecoverBytes(shares)
	return string(b), err
}
