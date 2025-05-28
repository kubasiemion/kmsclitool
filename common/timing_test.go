package common

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"testing"
	"time"
)

func TestTiming(t *testing.T) {
	match := regexp.MustCompile("^7E57$")
	start := time.Now()
	key := make([]byte, 32)
	for i := 0; i < 10001; i++ {
		rand.Read(key)
		adb := CRCAddressFromPub(Scalar2Pub(key))
		match.MatchString(string(adb))
	}
	lap := time.Since(start)
	fmt.Println(lap)

	start = time.Now()
	for i := 0; i < 10001; i++ {
		for j := 0; j < 32; j++ {
			key[j]++
			if key[j] != 0 {
				break
			}
		}
		adb := CRCAddressFromPub(Scalar2Pub(key))
		match.MatchString(string(adb))
	}
	lap = time.Since(start)
	fmt.Println(lap)

}

func TestGenerateVanityKey(t *testing.T) {
	_, addr, _, _, lap := TimeConstraindedVanityKey("07E57$", true, 120)
	fmt.Println(lap)
	fmt.Println(addr)

}
