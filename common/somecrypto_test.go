package common

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCRC(t *testing.T) {
	adrstr := "0xd41c057fd1c78805AAC12B0A94a405c0461A6FBb"

	adrbytes, e := hex.DecodeString(adrstr[2:])
	if e != nil {
		t.Error(e)
	}

	adrstr2 := CRCAddressString(adrbytes)
	fmt.Println(adrstr)
	fmt.Println(adrstr2)
	fmt.Println(addrKecc(adrbytes))

	rsa.GenerateKey(rand.Reader, 1024)
}
