package cmd

import (
	"encoding/hex"

	"github.com/spf13/cobra"
)

// generateKeyFileCmd represents the generateKeyFile command
var changePasswordCmd = &cobra.Command{
	Use:   "changePassword filename [-f newFilename] [--kdf kdf]",
	Short: "Changes password of a keyfile",
	Long:  `Changes password of an existing keyfile. Interactively asks for a new password (do not forget your choice!).`,
	Run:   changePassword,
}

func init() {
	rootCmd.AddCommand(changePasswordCmd)

	changePasswordCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	changePasswordCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")

}

func changePassword(cmd *cobra.Command, args []string) {
	fw := new(FileWrapper)
	if len(genFilename) == 0 {
		genFilename = args[0]
	}
	fw.readKeyFile(cmd, args)
	privhex = hex.EncodeToString(fw.KeyFile.Plaintext)

	generateKeyFile(cmd, args)

}
