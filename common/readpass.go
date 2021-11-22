package common

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

//Reading a password on a CLI without echoing it
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
