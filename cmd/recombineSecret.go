package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/poly"
	"github.com/spf13/cobra"
)

// splitSecretCmd
var recombineSecretCmd = &cobra.Command{
	Use:   "recombineSecret [--fileptrn filename_pattern]",
	Short: "Recovers a secret from t/n files (shamir's scheme)",
	Long:  `Recovers a secret from t/n files (shamir's scheme)`,
	Run:   recombineSecret,
}

var fileRegex = regexp.MustCompile(`[\S]*[0-9]{2}.json`)

func recombineSecret(cmd *cobra.Command, args []string) {

	var filename string
	var filecount int
	if len(filenamePat) > 0 {
		filename = fmt.Sprintf("%s%02d.json", filenamePat, filecount)
	}
	for len(shares) == 0 || shares[0].D+1 > len(shares) {

		fmt.Printf("Filename for the next share [%s]\n", filename)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if len(scanner.Text()) > 0 {
			filename = scanner.Text()
		}
		readShare(filename)

		if len(shares) > 0 {
			fmt.Printf("%v/%v\n", len(shares), shares[0].D+1)
		}

	}

}

var shares []poly.Share

func readShare(filename string) (enough bool) {
	kf, err := common.ReadAndProcessKeyfile(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if kf.Address == splitAddress {
		share := new(poly.Share)
		err := json.Unmarshal(kf.Plaintext, share)
		if err != nil {
			fmt.Println(err)
			return false
		}
		shares = append(shares, *share)
		if len(shares) > share.D {
			return true
		}

	}
	return

}

/*
func splitKey(key []byte) {

	shares, err := poly.SplitBytes(key, nshares, threshold, *secp256k1.S256().P)
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

func recoverSecret(sh []poly.Share) ([]byte, error) {
	i, e := poly.Lagrange(sh)
	if i != nil {
		return i.Bytes(), e
	}
	return nil, e

}

var secret, filenamePat string
var nshares, threshold int
*/
func init() {
	rootCmd.AddCommand(recombineSecretCmd)

	recombineSecretCmd.Flags().StringVarP(&filenamePat, "fileptrn", "f", "", "--firstfile filename_Pattern")

}
