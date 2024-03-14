package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/gf256"
	"github.com/spf13/cobra"
)

// splitStringCmd
var recoverStringCmd = &cobra.Command{
	Use:   "recoverString --fileptrn filename_pattern -n shares -t theshold -s secret",
	Short: "Recovers a secret form t out of n shares  (shamir's scheme)",
	Long:  `Recovers a secret form t out of n shares  (shamir's scheme)`,
	Run:   recoverStringWrap,
}

func recoverStringWrap(cmd *cobra.Command, args []string) {
	recoverStringInternal()
}

func recoverStringInternal() {
	var filename string
	var filecount int
	var shares []gf256.Share
	for len(shares) == 0 || int(shares[0].Degree)+1 > len(shares) {
		filename = fmt.Sprintf("%s%02d.json", filenamePat4String, filecount)
		prompt := fmt.Sprintf("Filename for the next share [%s]:\n", filename)
		str, err := common.ReadString(prompt)
		if len(str) > 0 {
			filename = str
		}
		if err != nil {
			fmt.Println(err)
			continue
		}

		readGFShare(filename, &shares)
		filecount++
		if len(shares) > 0 {
			fmt.Printf("%v/%v\n", len(shares), shares[0].Degree+1)
		} else {
			fmt.Println("No shares")

		}

	}
	rec, err := gf256.RecoverBytes(shares)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(rec))
}

func readGFShare(filename string, shares *[]gf256.Share) (enough bool) {
	kf, err := common.ReadAndProcessKeyfile(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}
	//if kf.Address == splitAddress {
	share := new(gf256.Share)
	err = json.Unmarshal(kf.Plaintext, share)
	if err != nil {
		fmt.Println(err)
		return false
	}
	*shares = append(*shares, *share)
	if len(*shares) > int(share.Degree) {
		return true
	}

	//}
	return

}

func init() {
	rootCmd.AddCommand(recoverStringCmd)

	recoverStringCmd.Flags().StringVarP(&filenamePat4String, "fileptrn", "f", "splitkey", "--fileptrn filename_Pattern")

}

// SplitAndWrapString splits a string and wraps the shares in keyfiles
// The keyfiles ARE NOT encrypted
