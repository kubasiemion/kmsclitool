package cmd

import (
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

func calculateAddress(cmd *cobra.Command, args []string) {

	if len(addr) > 20 {
		fmt.Printf("Wrong address length: %v", len(addr))
		return
	}
	addr = common.Pad(addr, 20)
	baddr, err := common.CalcCREATEAddress(addr, nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	caddr := common.CRCAddressString(baddr)
	fmt.Printf("Deployer: %x, Nonce: %v\n", addr, nonce)
	fmt.Printf("Contract address: %s\n", caddr)
}

var calculateAddressCmd = &cobra.Command{
	Use:   "calculateAddress -a <address> -n <nonce>",
	Short: "Calculate CREATE contract address.",
	Long:  "Calculate CREATE contract address from deployer address and nonce.",
	Run:   calculateAddress,
}

func init() {
	rootCmd.AddCommand(calculateAddressCmd)

	calculateAddressCmd.Flags().BytesHexVarP(&addr, "addr", "a", nil, "Ethereum address of the Deployer")
	calculateAddressCmd.Flags().UintVarP(&nonce, "nonce", "n", 0, "Nonce of the Deployer")
	calculateAddressCmd.MarkFlagRequired("addr")
	calculateAddressCmd.MarkFlagRequired("nonce")

}

var addr []byte //Ethereum address of the Deployer]
var nonce uint
