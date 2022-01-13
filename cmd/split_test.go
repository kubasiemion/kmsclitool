package cmd

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSplit(t *testing.T) {
	secret := []byte("Jasio Karuzela")
	sh, err := split(secret, 3, 2)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(sh)
	rec, err := recoverSecret(sh[:2])
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(secret, rec) != 0 {
		t.Error("secret not recovered from [:2]")
	}

	rec, err = recoverSecret(sh[1:])
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(secret, rec) != 0 {
		t.Error("secret not recovered from [1:]")
	}

	sh2, err := split(secret, 4, 3)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(sh2)
	falseshares := append(sh[:1], sh2...)
	rec, err = recoverSecret(falseshares)
	if err == nil {
		t.Error("mismatching shares not detected")
	}

}
