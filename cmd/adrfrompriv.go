package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(adrFromPrivCmd)
	adrFromPrivCmd.Flags().BytesHexVarP(&privhex, "privkey", "p", nil, "--privkey privkey_in_hex")
}

var privhex []byte

var adrFromPrivCmd = &cobra.Command{
	Use:   "addrFromPriv",
	Short: "derive address from a given private key",
	Long:  "long",
	Run:   adrFromPriv,
}

func adrFromPriv(cmd *cobra.Command, args []string) {
	if len(privhex) == 0 {
		fmt.Println("No private key given")
		return
	}

	x, y := secp256k1.S256().ScalarBaseMult(privhex)
	fmt.Println("x:", hex.EncodeToString(x.Bytes()))
	fmt.Println("y:", hex.EncodeToString(y.Bytes()))
	kecc := common.Keccak256(append(common.Pad(x.Bytes(), 32), common.Pad(y.Bytes(), 32)...))
	addr = kecc[12:]
	fmt.Println(common.CRCAddressString(addr))
}
