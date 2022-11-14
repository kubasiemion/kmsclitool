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

		addr := hex.EncodeToString((Scalar2Pub(ethkey)))

		if len(seed.Find([]byte(addr))) > 0 {
			fmt.Println(hex.EncodeToString(ethkey))
			fmt.Println(i, addr)
			break
		}
	}

}

func TestMatch(t *testing.T) {
	fmt.Println(seed.FindAllString("D1e6aaad1e6bbbD1E6cccd1E6", -1))
}

var seed = regexp.MustCompile("(?i)^d1e6")
