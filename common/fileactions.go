package common

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

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
		kf.Filename = actualfilename
	}
	return os.WriteFile(actualfilename, jsonbytes, 0644)
}
