package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/poly"
	"github.com/spf13/cobra"
)

var recoverEthKeyCmd = &cobra.Command{
	Use:   "recoverEthKey [--fileptrn filename_pattern]",
	Short: "Recovers an Eth key from t/n files (shamir's scheme)",
	Long:  `Recovers an Eth key from t/n files (shamir's scheme)`,
	Run:   recoverEthKey,
}

func recoverEthKey(cmd *cobra.Command, args []string) {
	key, err := recoverKeyFromKeyFiles()
	if err != nil {
		fmt.Println(err)
		return
	}
	key = common.Pad(key, 32)
	//TODO wrap it
	fmt.Printf("%x\n", key)

}

func recoverKeyFromKeyFiles() ([]byte, error) {

	var filename string
	var filecount int
	var shares []poly.Share

	for len(shares) == 0 || shares[0].D+1 > len(shares) {
		filename = fmt.Sprintf("%s%02d.json", filenamePat4Key, filecount)
		prompt := fmt.Sprintf("Filename for the next share [%s]:\n", filename)
		str, err := common.ReadString(prompt)
		if len(str) > 0 {
			filename = str
		}
		if err != nil {
			fmt.Println(err)
			continue
		}

		readPolyShare(filename, &shares)
		filecount++
		if len(shares) > 0 {
			fmt.Printf("%v/%v\n", len(shares), shares[0].D+1)
		}

	}
	return recoverPolySecret(shares)

}

// TODO remove this
func recoverPolySecret(sh []poly.Share) ([]byte, error) {
	i, e := poly.Lagrange(sh)
	if e != nil {
		return nil, e
	}
	if i != nil {
		return i.Bytes(), e
	}
	return nil, fmt.Errorf("No secret recovered")

}

func readPolyShare(filename string, shares *[]poly.Share) (enough bool) {
	kf, err := common.ReadAndProcessKeyfile(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if kf.Address == common.SplitAddress {
		share := new(poly.Share)
		err := json.Unmarshal(kf.Plaintext, share)
		if err != nil {
			fmt.Println(err)
			return false
		}
		*shares = append(*shares, *share)
		if len(*shares) > share.D {
			return true
		}

	}
	return

}

var filenamePat4Key string

func init() {
	rootCmd.AddCommand(recoverEthKeyCmd)

	recoverEthKeyCmd.Flags().StringVarP(&filenamePat4Key, "fileptrn", "f", "splitKey", "--fileptrn filename_Pattern")

}
