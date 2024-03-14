package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/poly"
	"github.com/spf13/cobra"
)

const splitAddress = "File contains a shard of a key"

// splitEthKeyCmd
var splitEthKeyCmd = &cobra.Command{
	Use:   "splitEthKey --fileptrn filename_pattern -n shares -t theshold -p privkey",
	Short: "Split an Eth key t/n (shamir's scheme)",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   splitEthKey,
}

func splitEthKey(cmd *cobra.Command, args []string) {
	if len(privhex) == 0 {
		fmt.Println("No key to split")
		return
	}
	if len(privhex) > 32 {
		fmt.Printf("Key too long: (%v bytes)", len(privhex))
		return
	}
	kfs, err := splitKey(privhex, numshares, threshold)
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

func splitKey(key []byte, n, t int) ([]*common.Keyfile, error) {

	shares, err := poly.SplitBytes(key, n, t, *secp256k1.S256().P)
	if err != nil {
		return nil, err
	}
	uuidbase := common.NewUuid()
	secrets := make([][]byte, len(shares))
	for i, sh := range shares {
		secrets[i], err = json.Marshal(sh)
		if err != nil {
			fmt.Println("Error serializing to json:", err)
			return nil, err
		}
	}
	//kf, err := WrapSecret(filename, uuidbase.NthUuidString(i, 1), shenc, splitAddress)

	return WrapNSecrets(filenamePat4Key, uuidbase, secrets, splitAddress)
}

func WrapNSecrets(filenameptrn string, idptrn *common.Uuid, plaintexts [][]byte, addressTextPtrn string) ([]*common.Keyfile, error) {
	kfs := make([]*common.Keyfile, len(plaintexts))
	var err error
	for i, sec := range plaintexts {
		filename := fmt.Sprintf("%s%02x.json", filenameptrn, i)
		id := idptrn.Next()
		kfs[i], err = WrapSecret(filename, id, sec, addressTextPtrn)
		if err != nil {
			return nil, err
		}

	}
	return kfs, nil
}

func WrapSecret(filename string, id string, plaintext []byte, addressText string) (*common.Keyfile, error) {
	keyf := &common.Keyfile{}
	keyf.Plaintext = plaintext
	keyf.ID = id
	keyf.Crypto.Cipher = encalg
	keyf.Crypto.Kdf = kdf
	pass, err := common.SetPassword(fmt.Sprintf("Password for %s:", filename))
	if err != nil {
		return nil, err
	}
	keyf.Hint, _ = common.GetPasswordHint()
	keyf.Address = addressText
	if err != nil {
		return nil, err
	}
	err = common.EncryptAES(keyf, plaintext, pass)
	if err != nil {
		return nil, err
	}
	keyf.Filename = filename
	return keyf, nil
}

var numshares, threshold int

func init() {
	rootCmd.AddCommand(splitEthKeyCmd)

	splitEthKeyCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	splitEthKeyCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	splitEthKeyCmd.Flags().StringVarP(&filenamePat4Key, "fileptrn", "f", "splitKey", "--fileptrn filename_Pattern")
	splitEthKeyCmd.Flags().BytesHexVarP(&privhex, "privkey", "s", nil, "--privkey your_secret key (in hex)")
	splitEthKeyCmd.Flags().IntVarP(&numshares, "nshares", "n", 2, "--nshares number_of_shares")
	splitEthKeyCmd.Flags().IntVarP(&threshold, "threshold", "t", 2, "--theshold no_of_shares_needed")

}
