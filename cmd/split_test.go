package cmd

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/proveniencenft/primesecrets/gf256"
	"github.com/proveniencenft/primesecrets/poly"
)

/*
func TestKeySplit(t *testing.T) {

		key := []byte("Jasio Karuzela")
		key = common.Pad(key, 32)
		shares := splitKey(key, 3, 2)
		rec1, err := recoverSecret(shares[:2])
		if err != nil {
			t.Error(err)
		}
		if bytes.Compare(key, rec1) != 0 {
			t.Error("secret not recovered from [:2]")
		}
		rec2, err := recoverSecret(shares[1:])
		if err != nil {
			t.Error(err)
		}
		if bytes.Compare(key, rec2) != 0 {
			t.Error("secret not recovered from [1:]")

		}
	recombineEthKey(nil, nil)
}
*/

func TestSplit(t *testing.T) {
	secret := []byte("Jasio Karuzela")
	sh, err := poly.SplitBytes(secret, 2, 2, *secp256k1.S256().P)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(sh)
	rec, err := recoverPolySecret(sh[:2])
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(secret, rec) != 0 {
		t.Error("secret not recovered from [:2]")
	}

	rec, err = recoverPolySecret(sh[:])
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(secret, rec) != 0 {
		t.Error("secret not recovered from [1:]")
	}

	sh2, err := poly.SplitBytes(secret, 4, 3, *secp256k1.S256().P)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(sh2)
	falseshares := append(sh[:1], sh2...)
	rec, err = recoverPolySecret(falseshares)
	if err == nil {
		t.Error("mismatching shares not detected")
	}

	secretString := "Duda Jasio"
	shares, err := SplitString(secretString, 3, 2)
	if err != nil {
		t.Errorf("Bad shares: %s", err)
	}
	b, err := gf256.RecoverBytes(shares)
	if err != nil {
		t.Errorf("Error reassembling string: %s", err)
	}
	fmt.Println(string(b))

	//Test duplicating a share
	nshares := []poly.Share{}
	nshares = append(nshares, sh[0])
	nshares = append(nshares, sh[0])
	rec, err = recoverPolySecret(nshares)
	fmt.Println(rec, err)

}

func TestSplitString(t *testing.T) {
	bstr := []byte("Jasio Karuzela")
	shares, err := SplitString(string(bstr), 3, 2)
	if err != nil {
		t.Error(err)
	}
	rec1, err := gf256.RecoverBytes(shares[:2])
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(rec1, bstr) {
		t.Error("secret not recovered from [:2]")
	}
	rec2, err := gf256.RecoverBytes(shares[1:])
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(rec2, bstr) {
		t.Error("secret not recovered from [1:]")
	}
}
