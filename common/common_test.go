package common

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRead(t *testing.T) {
	kf, err := ReadKeyfile("../0xFEEd0CcCc217E4Dc52EA262445451A072FAF8D1b.json")
	if err != nil {
		t.Error(err)
	}
	key, err := kf.KeyFromPass([]byte("aaaaaa"))
	if err != nil {
		t.Error(err)
	}
	if kf.VerifyMAC(key) != nil {
		t.Error("MAC verification error")
	}

}

func TestAddress(t *testing.T) {
	faddr, _ := hex.DecodeString("d9145CCE52D386f254917e481eB44e9943F39138")
	var i uint
	for i = 0; i < 4; i++ {
		caddr, err := CalcCREATEAddress(faddr, i)
		fmt.Println(hex.EncodeToString(caddr), err)
	}
}
