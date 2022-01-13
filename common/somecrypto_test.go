package common

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCRC(t *testing.T) {
	adrstr := "0x2d955c0C6DE2887708b13AB15a95C4Fd7B0B7D25"

	adrbytes, e := hex.DecodeString(adrstr[2:])
	if e != nil {
		t.Error(e)
	}

	adrstr2 := CRCAddressString(adrbytes)
	fmt.Println(adrstr)
	fmt.Println(adrstr2)
	fmt.Println(addrKecc(adrbytes))
}
