package common

import (
	"bytes"
	"encoding/json"
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

func ProcessJsonBytes(jsonbytes []byte) (keyfile *Keyfile, err error) {
	kf := Keyfile{}
	err = json.Unmarshal(jsonbytes, &kf)
	switch kf.Crypto.Kdf {
	case "scrypt":
		ksp := new(KdfScryptparams)
		err = json.Unmarshal(kf.Crypto.KdfparamsPack, ksp)
		kf.Crypto.KdfScryptParams = *ksp
	case "pbkdf2":
		kpb := new(KdfPbkdf2params)
		err = json.Unmarshal(kf.Crypto.KdfparamsPack, kpb)
		kf.Crypto.KdfPbkdf2params = *kpb

	}
	return &kf, err
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

func (keyfile *Keyfile) KeyFromPass(pass []byte) (key []byte, err error) {
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
	return
}
