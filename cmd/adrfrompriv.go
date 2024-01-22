package cmd

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(adrFromPrivCmd)
	adrFromPrivCmd.Flags().StringVarP(&privhex, "privkey", "p", "", "--privkey privkey_in_hex")
}

var privhex string

var adrFromPrivCmd = &cobra.Command{
	Use:   "adrFromPriv",
	Short: "derive address from a given private key",
	Long:  "long",
	Run:   adrFromPriv,
}

func adrFromPriv(cmd *cobra.Command, args []string) {
	if len(privhex) == 0 {
		fmt.Println("No private key given")
		return
	}

	if len(privhex) > 2 && privhex[:2] == "0x" {
		privhex = privhex[2:]
	}
	priv, err := hex.DecodeString(privhex)
	if err != nil {
		fmt.Println("Error decoding the private key:", err)
		return
	}
	_, pub := secp256k1.PrivKeyFromBytes(priv)
	kecc := common.Keccak256(append(pub.X.Bytes(), pub.Y.Bytes()...))
	addr := kecc[12:]
	fmt.Println(hex.EncodeToString(addr))

	x, y := secp256k1.S256().ScalarBaseMult(priv)
	fmt.Println("x:", hex.EncodeToString(x.Bytes()))
	fmt.Println("y:", hex.EncodeToString(y.Bytes()))
	kecc = common.Keccak256(append(Padd(x), Padd(y)...))
	addr = kecc[12:]
	fmt.Println(hex.EncodeToString(addr))
}

func Padd(s *big.Int) []byte {
	xb := s.Bytes()
	if len(xb) < 32 {
		fmt.Println("Padding")
		fill := make([]byte, 32-len(xb))
		xb = append(fill, xb...)
	}
	return xb
}
