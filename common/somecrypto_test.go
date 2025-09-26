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

func TestEncryptCTR(t *testing.T) {

	keyf := &Keyfile{}
	keyf.Crypto.Cipher = "aes-128-ctr"
	keyf.Crypto.Kdf = KdfScrypt
	password := []byte("password")
	plaintext := []byte("plaintext")
	EncryptAES(keyf, plaintext, password, 0)

	fmt.Println(keyf.Crypto.Ciphertext)

	err := keyf.Decrypt(password)
	if err != nil {
		t.Error(err)
	}
	if string(keyf.Plaintext) != string(plaintext) {
		t.Error("Decryption error")
	} else {
		fmt.Println("Decryption OK for AES-128-CTR")
	}

	keyf.Crypto.Cipher = "aes-128-ctr"
	EncryptAES(keyf, plaintext, password, 0)
	err = keyf.Decrypt(password)
	if err != nil {
		t.Error(err)
	}
	if string(keyf.Plaintext) != string(plaintext) {
		t.Error("Decryption error")
	} else {
		fmt.Println("Decryption OK for AES-256-CTR")
	}

	keyf.Crypto.Cipher = "aes-256-gcm"
	EncryptAES(keyf, plaintext, password, 0)
	fmt.Println(keyf.Crypto.Ciphertext)

	err = keyf.Decrypt(password)
	if err != nil {
		t.Error(err)
	}
	if string(keyf.Plaintext) != string(plaintext) {
		t.Error("Decryption error")
	} else {
		fmt.Println("Decryption OK for AES-256-GCM")
	}

	keyf.Crypto.Cipher = "aes-128-gcm"
	EncryptAES(keyf, plaintext, password, 0)
	fmt.Println(keyf.Crypto.Ciphertext)

	err = keyf.Decrypt(password)
	if err != nil {
		t.Error(err)
	}
	if string(keyf.Plaintext) != string(plaintext) {
		t.Error("Decryption error")
	} else {
		fmt.Println("Decryption OK for AES-128-GCM")
	}

}

// test path convertion
func TestPath(t *testing.T) {
	path := `m/44'/60'/0'/0/0`
	ipath, err := PathToUint32(path)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ipath)
	path2 := `m/44'/60/0'/0/0`
	ipath2, err := PathToUint32(path2)
	if err != nil {
		t.Error(err)
	}
	for i, v := range ipath2 {
		fmt.Printf("%v: %x\n", i, v)
	}
}

func TestDerive(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	seed := []byte("12345678901234567890123456789012")
	rkey, err := RootKeyFromKey(key, seed)
	if err != nil {
		t.Error(err)
	}
	spath := `m/44'/60'/0'/0/1/17'`
	path, err := PathToUint32(spath)
	if err != nil {
		t.Error(err)
	}

	ckey, err := DeriveChildKey(rkey, path)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(rkey)
	fmt.Println(ckey, hex.EncodeToString(ckey.Key), hex.EncodeToString(ckey.ChainCode), ckey.Depth, ckey.ChildNumber, ckey.FingerPrint, ckey.Version)

}

func TestVanity(t *testing.T) {
	//vanity := "^B00B5"
	var vanity = ""
	key, addr, _, _, err := TimeConstraindedVanityKey(vanity, false, 200)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(addr)
	fmt.Printf("0x%x\n", key)
}
