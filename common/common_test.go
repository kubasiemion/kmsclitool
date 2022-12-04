package common

import (
	"testing"
)

func TestRead(t *testing.T) {
	kf, err := ReadKeyfile("../0xFEEd0CcCc217E4Dc52EA262445451A072FAF8D1b.json")
	if err != nil {
		t.Error(err)
	}
	key, err := kf.KeyFromPass([]byte("bbbbbb"))
	if err != nil {
		t.Error(err)
	}
	kf.VerifyMAC(key)
}
