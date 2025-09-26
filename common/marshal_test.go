package common

import (
	"encoding/json"
	"fmt"
	"testing"
)

/*
func TestUnmarshal(t *testing.T) {
	kf, err := ReadKeyfile("../0xFEEd0CcCc217E4Dc52EA262445451A072FAF8D1b.json")
	fmt.Println(err)
	fmt.Println(kf)
	b, err := os.ReadFile("../0xFEEd0CcCc217E4Dc52EA262445451A072FAF8D1b.json")
	kf2 := new(Keyfile)
	kf2.UnmarshalJSON(b)
	fmt.Println(kf2)

}
*/

func TestMarshalScrypt(t *testing.T) {
	// Example JSON for a keyfile using Scrypt
	scryptJSON := `{
		"version": 3,
		"id": "c16193b2-6d43-41c3-bf6b-f41710926d2d",
		"address": "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
		"crypto": {
			"ciphertext": "685c721c834a04d2c8843936a287a9ce7e26d702d849a9446d37651c5f356d77",
			"cipherparams": {
				"iv": "32c4b7b258673a0e10411a5806e23267"
			},
			"cipher": "aes-128-ctr",
			"kdf": "scrypt",
			"kdfparams": {
				"dklen": 32,
				"n": 262144,
				"r": 8,
				"p": 1,
				"salt": "a8b79234ae24177d4c264c125d0c754d9c79294e5a95f87b8979116e0f9b6c16"
			},
			"mac": "28114f5cfd71e21b023f2f81640a6b252ef2e50587a8b4b1a41853b054817a78"
		}
	}`

	var kf Keyfile
	if err := json.Unmarshal([]byte(scryptJSON), &kf); err != nil {
		fmt.Println("Error unmarshaling Scrypt JSON:", err)
	} else {
		params := kf.Crypto.Kdfparams.(ScryptParams)
		fmt.Println(params)
	}
}
