package cmd

import (
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

// generateKeyFileCmd represents the generateKeyFile command
var changePasswordCmd = &cobra.Command{
	Use:   "changePassword filename [-f newFilename] [--kdf kdf --out newFilename]",
	Short: "Changes password of a keyfile",
	Long:  `Changes password of an existing keyfile. Interactively asks for a new password (do not forget your choice!).`,
	Run:   changePassword,
}

func init() {
	rootCmd.AddCommand(changePasswordCmd)

	changePasswordCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	changePasswordCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")
	changePasswordCmd.Flags().StringVar(&outfile, "out", "", "--out new_filename")

}

func changePassword(cmd *cobra.Command, args []string) {

	if len(genFilename) == 0 {
		genFilename = args[0]
	}
	kf, err := common.ReadAndProcessKeyfile(genFilename)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Enter the new password")
	privhex = kf.Plaintext
	pass, err := common.SetPassword("New password:")
	if err != nil {
		fmt.Println(err)
		return
	}
	kf.Hint, err = common.GetPasswordHint()
	if err != nil {
		fmt.Println(err)
	}
	common.EncryptAES(kf, kf.Plaintext, pass)
	common.WriteKeyfile(kf, outfile)

}
