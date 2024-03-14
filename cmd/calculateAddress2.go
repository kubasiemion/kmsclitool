package cmd

import (
	"fmt"

	"github.com/proveniencenft/kmsclitool/common"
	"github.com/spf13/cobra"
)

var codehash []byte //Hash of the bytecode
var salt []byte     //Salt for CREATE2

func calculateAddress2(cmd *cobra.Command, args []string) {

	//Deploying contract address

	deployer := common.Pad(addr, 20)
	codehash = common.Pad(codehash, 32)
	salt = common.Pad(salt, 32)
	//fmt.Printf("%x\n%x\n%x\n", deployer, codehash, salt)
	baddr, err := common.CalcCREATE2Address(deployer, codehash, salt)
	if err != nil {
		fmt.Println(err)
		return
	}
	caddr := common.CRCAddressString(baddr)
	fmt.Printf("Deployer: %x, Nonce: %v\n", deployer, nonce)
	fmt.Printf("Contract address: %s\n", caddr)
}

var calculateAddress2Cmd = &cobra.Command{
	Use:   "calculateAddress2 -a <address> ",
	Short: "Calculate CREATE2 contract address.",
	Long:  "Calculate CREATE contract address from deployer address and nonce.",
	Run:   calculateAddress,
}

func init() {
	rootCmd.AddCommand(calculateAddress2Cmd)
	calculateAddress2Cmd.Flags().BytesHexVarP(&addr, "addr", "a", nil, "Ethereum address of the Deployer")
	calculateAddress2Cmd.MarkFlagRequired("addr")
	calculateAddress2Cmd.Flags().BytesHexVarP(&codehash, "codehash", "c", nil, "Hash of the contract bytecode")
	calculateAddress2Cmd.Flags().BytesHexVarP(&salt, "salt", "s", nil, "Salt for CREATE2")
	calculateAddress2Cmd.MarkFlagRequired("codehash")
	calculateAddress2Cmd.MarkFlagRequired("salt")

}
