package cmd

import (
	"fmt"
	"os"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/gf256"
	"github.com/spf13/cobra"
)

// splitStringCmd
var recoverFileCmd = &cobra.Command{
	Use:   "recoverFile --fileptrn filename_pattern -n shares -t theshold -s secret",
	Short: "Recovers a secret form t out of n shares  (shamir's scheme)",
	Long:  `Recovers a secret form t out of n shares  (shamir's scheme)`,
	Run:   recoverFile,
}

func recoverFile(cmd *cobra.Command, args []string) {
	var filename string
	var filecount int
	var shares []gf256.Share
	for len(shares) == 0 || int(shares[0].Degree)+1 > len(shares) {

		filename = fmt.Sprintf("%s%02d.json", filenamePat4File, filecount)
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
	os.WriteFile(outfile, rec, 0644)
}

var outfile string
var filenamePat4File string

func init() {
	rootCmd.AddCommand(recoverFileCmd)

	recoverFileCmd.Flags().StringVarP(&filenamePat4File, "fileptrn", "f", "splitFile", "--fileptrn filename_Pattern")
	recoverFileCmd.Flags().StringVar(&outfile, "out", "", "--out filename")
	recoverFileCmd.MarkFlagRequired("out")
}

// SplitAndWrapString splits a string and wraps the shares in keyfiles
// The keyfiles ARE NOT encrypted
