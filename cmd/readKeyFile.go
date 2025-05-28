package cmd

import (
	"fmt"

	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

// readKeyFileCmd represents the readKeyFile command
func newReadKeyFileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "readKeyFile filename [-v]",
		Short: "Read an Ethereum key file",
		Long:  `Read an Ethereum key file. In verbose mode, reveals the secret`,
		Run:   readKeyFileCobraWrapper,
	}
}

func readKeyFileCobraWrapper(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Println("missing or ambiguous filename")
		return
	}
	var err error
	kf, err := common.ReadAndProcessKeyfile(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	DisplayKeyFile(kf, common.Verbose)

	return
}

func init() {
	rcfc := newReadKeyFileCmd()
	rootCmd.AddCommand(rcfc)

	rcfc.Flags().BoolVarP(&common.Verbose, "verbose", "v", false, "Verbose output")
}

func DisplayKeyFile(kf *common.Keyfile, verbose bool) {

	if kf.Address == splitAddress {
		id := "XX" + kf.ID[2:]

		fmt.Printf("%s from suite %s\n", splitAddress, id)
		return
	}

	prv, pubkeyec := secp256k1.PrivKeyFromBytes(kf.PrivKey)
	pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)
	fmt.Printf("Public key: \t%s\n", hex.EncodeToString(pubkeyeth))
	if verbose {
		fmt.Printf("Private key: \t%s\n", hex.EncodeToString(kf.PrivKey))
		if len(kf.ChainCode) > 0 {
			fmt.Printf("Chain code: \t%s\n", hex.EncodeToString(kf.ChainCode))
		}
		fmt.Println("D:", prv.D)
		fmt.Println("X:", pubkeyec.X)
		fmt.Println("Y:", pubkeyec.Y)
	}
	kecc := common.Keccak256(pubkeyeth)
	addr := kecc[12:]
	fmt.Printf("Ethereum addr: %s\n", common.CRCAddressString(addr))
	fmt.Printf("(in file: %s)\n", kf.Address)
	return
}
