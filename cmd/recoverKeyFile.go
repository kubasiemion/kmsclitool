package cmd

import (
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/proveniencenft/primesecrets/gf256"
	"github.com/spf13/cobra"
)

// splitStringCmd
var recoverKeyFileCmd = &cobra.Command{
	Use:   "recoverKeyFile --fileptrn filename_pattern -n shares -t theshold -s secret",
	Short: "Recovers a keyfile form t out of n shares  (shamir's scheme)",
	Long:  `Recovers a keyfile form t out of n shares  (shamir's scheme)`,
	Run:   recoverKeyFile,
}

func recoverKeyFile(cmd *cobra.Command, args []string) {
	var filename string
	var filecount int
	var shares []gf256.Share
	for len(shares) == 0 || int(shares[0].Degree)+1 > len(shares) {

		filename = fmt.Sprintf("%s%02d.json", filenamePat4KeyFile, filecount)
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
	var err error
	privhex, err = gf256.RecoverBytes(shares)
	if err != nil {
		fmt.Println(err)
		return
	}
	genFilename = outfile
	fmt.Println(genFilename)
	generateKeyFile(nil, nil)

}

func init() {
	rootCmd.AddCommand(recoverKeyFileCmd)
	recoverKeyFileCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	recoverKeyFileCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	recoverKeyFileCmd.Flags().StringVarP(&filenamePat4File, "fileptrn", "f", "splitKeyFile", "--fileptrn filename_Pattern")
	recoverKeyFileCmd.Flags().StringVar(&outfile, "out", "", "--out filename")
	recoverKeyFileCmd.MarkFlagRequired("out")
}

// SplitAndWrapString splits a string and wraps the shares in keyfiles
// The keyfiles ARE NOT encrypted
