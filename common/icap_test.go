package common

import (
	"fmt"
	"testing"

	ecommon "github.com/ethereum/go-ethereum/common"
)

func TestICAP(t *testing.T) {
	kf, err := ReadKeyfile("../w3test.json")
	if err != nil {
		t.Error(err)
	}
	kf.Decrypt([]byte("testpassword"))
	kf.DisplayKeyFile(false)

	address := "008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b"
	bts := ecommon.HexToAddress(address)
	icp := ToICAP(bts.Bytes())
	a2, err := FromICAP(icp)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("rec 0x%x\n", a2)

}
