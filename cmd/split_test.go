package cmd

import (
	"bytes"
	"testing"
)

func TestSplit(t *testing.T) {
	secret := []byte("Jasio Karuzela")
	sh, err := split(secret, 3, 2)
	if err != nil {
		t.Error(err)
	}

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

}
