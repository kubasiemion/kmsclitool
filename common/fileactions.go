package common

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/proveniencenft/primesecrets/gf256"
	"golang.org/x/crypto/ssh/terminal"
)

func SetPassword(prompt string) ([]byte, error) {
	var pass, p2 []byte
	var err error
	for {
		pass, err = ReadPassword(prompt)
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

func ReadString(prompt string) (string, error) {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text(), nil
}

// Reading a password on a CLI without echoing it
func ReadPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	defer fmt.Println()
	fd := int(os.Stdin.Fd())
	//Sadly terminal will not work under IDE, hence the 'else'
	if terminal.IsTerminal(fd) {
		return terminal.ReadPassword(fd)
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		pass := scanner.Bytes()
		return pass, nil
	}

}

// PRompt for a password hint
func GetPasswordHint() (string, error) {
	fmt.Print("Enter a password hint (optional): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	fmt.Println()
	return scanner.Text(), nil
}

// Reads and parses a json from a file
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
	kf.Filename = filename
	err = kf.UnmarshalKdfJSON()
	return kf, err

}

func ReadAndProcessKeyfile(filename string) (keyfile *Keyfile, err error) {

	keyfile, err = ReadKeyfile(filename)
	if err != nil {
		return keyfile, err
	}
	Label := fmt.Sprintf("Keyfile password (%s):", keyfile.Hint)
	pass, err := ReadPassword(Label)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	//TODO Handle the unencrypted kyefiles

	err = keyfile.Decrypt(pass)
	return
}

func WriteKeyfile(kf *Keyfile, filename string) error {
	jsonbytes, err := json.Marshal(kf)
	if err != nil {
		return err
	}
	actualfilename := filename
	if len(filename) == 0 {
		actualfilename = kf.Filename
	}
	if len(actualfilename) == 0 {
		actualfilename = kf.Address + ".json"

	}
	kf.Filename = actualfilename
	return os.WriteFile(actualfilename, jsonbytes, 0644)
}

func SplitBytesToFiles(secret []byte, fpattern string, numshares, threshold int, encalg, kdf, addrlabel string) {

	if len(secret) == 0 {
		fmt.Println("No secret to split")
		return
	}

	shares, err := gf256.SplitBytes(secret, numshares, threshold)
	if err != nil {
		fmt.Println(err)
		return
	}
	secrets := make([][]byte, len(shares))
	for i, sh := range shares {
		secrets[i], err = json.Marshal(sh)
		if err != nil {
			fmt.Println("Error serializing to json:", err)
			return
		}
	}
	uuidbase := NewUuid()
	kfs, err := WrapNSecrets(fpattern, uuidbase, secrets, encalg, kdf, addrlabel)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, kf := range kfs {
		err = WriteKeyfile(kf, "")
		if err != nil {
			fmt.Println(err)
			return
		}
	}

}

func WrapNSecrets(filenameptrn string, idptrn *Uuid, plaintexts [][]byte, encalg, kdf, addressTextPtrn string) ([]*Keyfile, error) {
	kfs := make([]*Keyfile, len(plaintexts))
	var err error
	for i, sec := range plaintexts {
		filename := fmt.Sprintf("%s%02x.json", filenameptrn, i)
		id := idptrn.Next()
		kfs[i], err = WrapSecret(filename, id, sec, encalg, kdf, addressTextPtrn)
		if err != nil {
			return nil, err
		}

	}
	return kfs, nil
}

func WrapSecret(filename string, id string, plaintext []byte, encalg, kdf, addressText string, dpass ...string) (*Keyfile, error) {
	keyf := &Keyfile{}
	keyf.Plaintext = plaintext
	keyf.ID = id
	keyf.Crypto.Cipher = encalg
	keyf.Crypto.Kdf = kdf
	var pass []byte
	var err error
	if len(dpass) > 0 {
		pass = []byte(dpass[0])
	} else {
		pass, err = SetPassword(fmt.Sprintf("Password for %s:", filename))
		if err != nil {
			return nil, err
		}
	}

	keyf.Hint, _ = GetPasswordHint()
	keyf.Address = addressText
	if err != nil {
		return nil, err
	}
	err = EncryptAES(keyf, plaintext, pass)
	if err != nil {
		return nil, err
	}
	keyf.Filename = filename
	return keyf, nil
}
