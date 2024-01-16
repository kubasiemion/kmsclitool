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
	keyf.Crypto.Kdf = "scrypt"
	password := []byte("password")
	plaintext := []byte("plaintext")
	EncryptAES(keyf, plaintext, password)

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
	EncryptAES(keyf, plaintext, password)
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
	EncryptAES(keyf, plaintext, password)
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
	EncryptAES(keyf, plaintext, password)
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
