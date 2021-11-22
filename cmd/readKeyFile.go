package cmd

import (
	"fmt"

	"encoding/hex"

	"github.com/btcsuite/btcd/btcec"
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

// readKeyFileCmd represents the readKeyFile command
var readKeyFileCmd = &cobra.Command{
	Use:   "readKeyFile filename",
	Short: "Read an Ethereum key file",
	Long:  `A longer description will follow soon.`,
	Run:   readKeyFile,
}

func readKeyFile(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Println("missing or ambiguous filename")
		return
	}
	kf, err := common.ReadAndProcessKeyfile(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	prv, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), kf.Plaintext)
	pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)
	fmt.Printf("Public key: \t%s\n", hex.EncodeToString(pubkeyeth))
	if common.Verbose {
		fmt.Printf("Private key: \t%s\n", hex.EncodeToString(kf.Plaintext))
		fmt.Println("D:", prv.D)
		fmt.Println("X:", pubkeyec.X)
		fmt.Println("Y:", pubkeyec.Y)
	}
	kecc := common.Keccak256(pubkeyeth)
	addr := kecc[12:]
	fmt.Printf("Ethereum addr: %s\n", hex.EncodeToString(addr))
	fmt.Printf("(in file: %s)\n", kf.Address)
	return
}

func init() {
	rootCmd.AddCommand(readKeyFileCmd)

	readKeyFileCmd.Flags().BoolVarP(&common.Verbose, "verbose", "v", false, "Verbose output")
}
