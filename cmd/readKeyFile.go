package cmd

import (
	"fmt"

	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

// readKeyFileCmd represents the readKeyFile command
func newReadKeyFileCmd(fw *FileWrapper) *cobra.Command {
	return &cobra.Command{
		Use:   "readKeyFile filename [-v]",
		Short: "Read an Ethereum key file",
		Long:  `A longer description will follow soon.`,
		Run:   fw.readKeyFile,
	}
}

type FileWrapper struct {
	KeyFile *common.Keyfile
}

func (fw *FileWrapper) readKeyFile(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Println("missing or ambiguous filename")
		return
	}
	var err error
	fw.KeyFile, err = common.ReadAndProcessKeyfile(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	if fw.KeyFile.Address == splitAddress {
		id := "xx" + fw.KeyFile.ID[2:]

		fmt.Printf("%s from suite %s\n", splitAddress, id)
		return
	}

	prv, pubkeyec := secp256k1.PrivKeyFromBytes(fw.KeyFile.Plaintext)
	pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)
	fmt.Printf("Public key: \t%s\n", hex.EncodeToString(pubkeyeth))
	if common.Verbose {
		fmt.Printf("Private key: \t%s\n", hex.EncodeToString(fw.KeyFile.Plaintext))
		fmt.Println("D:", prv.D)
		fmt.Println("X:", pubkeyec.X)
		fmt.Println("Y:", pubkeyec.Y)
	}
	kecc := common.Keccak256(pubkeyeth)
	addr := kecc[12:]
	fmt.Printf("Ethereum addr: %s\n", common.CRCAddressString(addr))
	fmt.Printf("(in file: %s)\n", fw.KeyFile.Address)
	return
}

func init() {
	rcfc := newReadKeyFileCmd(new(FileWrapper))
	rootCmd.AddCommand(rcfc)

	rcfc.Flags().BoolVarP(&common.Verbose, "verbose", "v", false, "Verbose output")
}
