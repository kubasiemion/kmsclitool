package cmd

import (
	"fmt"
	"os"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

//const splitFileLabel = "File contains a shard of a secret file"

// splitStringCmd
var fromMnemonicCmd = &cobra.Command{
	Use:   "fromMnemonic --in file_with_mnemonic",
	Short: "generate keyfiles from mnemonic",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   mnemonicWrapper,
}

func mnemonicWrapper(cmd *cobra.Command, args []string) {
	bt, err := os.ReadFile(infile)
	if err != nil {
		fmt.Println(err)
		return
	}
	mnem := string(bt)
	common.NormalizeMnemonic(&mnem)
	fmt.Println("mnemonic: ", mnem)
	derpath, err := common.PathToUint32(derivPathStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	kf, err := common.BIP32KeyFromMnemonic(mnem, "", "", derpath...)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("address: ", kf.Address)
	err = common.WriteKeyfile(kf, "")

}

func init() {
	rootCmd.AddCommand(fromMnemonicCmd)

	fromMnemonicCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	fromMnemonicCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	fromMnemonicCmd.Flags().StringVar(&infile, "in", "", "--in filename")
	fromMnemonicCmd.Flags().StringVarP(&genFilename, "file", "f", "", "--file filename")
	fromMnemonicCmd.MarkFlagRequired("in")
	fromMnemonicCmd.Flags().StringVar(&derivPathStr, "path", common.EthPath, "--path derivation_path")
	fromMnemonicCmd.Flags().BoolVar(&seedFromMnemonic, "seed", false, "--seed seed_directly_from_mnemonic")

}

var derivPathStr string
var seedFromMnemonic bool
