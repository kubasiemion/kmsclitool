package cmd

import "testing"

func TestPass(t *testing.T) {
	t.Log("Pass")

	genFilename = "testPass.json"
	privhex = []byte{2, 4, 8, 16, 32}
	generateKeyFile(nil, nil)
}
