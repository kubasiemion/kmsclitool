package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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

//Reads and parses a json from a file
func ReadKeyfile(filename string) (*Keyfile, error) {
	filebytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	kf := new(Keyfile)
	err = json.Unmarshal(filebytes, kf)
	if err != nil {
		return nil, err
	}
	err = kf.UnmarshalKdfJSON()
	return kf, err

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
	key, err := keyfile.KeyFromPass(pass)
	if err != nil {
		return
	}
	fmt.Println("Verifying MAC...")
	err = keyfile.VerifyMAC(key)
	if err != nil {
		return
	}
	keyfile.Plaintext, err = Decrypt(keyfile, key)
	return
}
