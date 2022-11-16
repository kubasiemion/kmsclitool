package common

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

func SetPassword() ([]byte, error) {
	var pass, p2 []byte
	var err error
	for {
		pass, err = ReadPassword("Password for the keyfile:")
		if err != nil {
			return nil, err
		}
		p2, err = ReadPassword("Repeat password:")
		if err != nil {
			return nil, err
		}
		if len(pass) < 6 {
			fmt.Print("Password too short, try again\n\n")
			continue
		}
		if bytes.Equal(pass, p2) {
			return pass, nil
		}
		fmt.Print("Passwords do not match, try again\n\n")
	}
}

func ReadAndProcessKeyfile(filename string) (keyfile *Keyfile, err error) {

	keyfile, err = ReadKeyfile(filename)
	if err != nil {
		return keyfile, err
	}
	pass, err := ReadPassword("Keyfile password:")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	//TODO Handle the unencrypted kyefiles

	//derive the key from password
	var key []byte
	switch keyfile.Crypto.Kdf {
	case "scrypt":
		key, err = KeyFromPassScrypt(pass, keyfile.Crypto.KdfScryptParams)
		if err != nil {
			return
		}

	case "pbkdf2":
		key, err = KeyFromPassPbkdf2(pass, keyfile.Crypto.KdfPbkdf2params)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("Unsupported KDF: " + keyfile.Crypto.Kdf)
		return
	}
	//Verify MAC
	//read the ciphertext
	citx, err := hex.DecodeString(keyfile.Crypto.Ciphertext)
	if err != nil {
		return
	}

	//verify mac
	mymac := hex.EncodeToString(Keccak256(append(key[16:32], citx...)))

	if mymac != keyfile.Crypto.Mac {
		err = fmt.Errorf("MAC verification failed")
	}

	keyfile.Plaintext, err = Decrypt(keyfile, key)
	return
}
