package common

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"
)

func TestAddress(t *testing.T) {
	ethkey := make([]byte, 32)

	for i := 0; ; i++ {
		rand.Read(ethkey)

		_, addr := Scalar2Pub(ethkey)
		haddr := hex.EncodeToString(addr)

		if len(seed.Find([]byte(haddr))) > 0 {
			fmt.Println(hex.EncodeToString(ethkey))
			fmt.Println(i, haddr)
			break
		}
	}

}

var seed = regexp.MustCompile("^5eed5")
