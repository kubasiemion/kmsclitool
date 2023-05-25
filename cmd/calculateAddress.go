package cmd

import (
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

func calculateAddress(cmd *cobra.Command, args []string) {

	deployer, err := common.ParseHexString(addr)
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(deployer) > 20 {
		fmt.Printf("Wrong address length: %v", len(deployer))
		return
	}
	dep20 := make([]byte, 20)
	copy(dep20[20-len(deployer):], deployer) //padding
	baddr, err := common.CalcCREATEAddress(dep20, nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	caddr := common.CRCAddressString(baddr)
	fmt.Printf("Deployer: %x, Nonce: %v\n", dep20, nonce)
	fmt.Printf("Contract address: %s\n", caddr)
}

var calculateAddressCmd = &cobra.Command{
	Use:   "calculateAddress",
	Short: "N/A",
	Long:  "N/A",
	Run:   calculateAddress,
}

func init() {
	rootCmd.AddCommand(calculateAddressCmd)

	calculateAddressCmd.Flags().StringVarP(&addr, "addr", "a", "", "Ethereum address of the Deployer")
	calculateAddressCmd.Flags().UintVarP(&nonce, "nonce", "n", 0, "Nonce of the Deployer")

}

var addr string
var nonce uint
