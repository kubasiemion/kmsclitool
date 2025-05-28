package common

import (
	"bytes"
	"fmt"
	"testing"

	"crypto/rand"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func TestMnemon(t *testing.T) {
	m := metamaskSeed
	NormalizeMnemonic(&m)
	seed, err := bip39.NewSeedWithErrorChecking(m, "")
	if err != nil {
		t.Errorf("Failed to create seed: %v", err)
	}
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Errorf("Failed to create master key: %v", err)
	}
	fmt.Println(CRCAddressFromPub(Scalar2Pub(masterKey.Key)))
	path, err := PathToUint32(EthPath)
	if err != nil {
		t.Errorf("Failed to convert path: %v", err)
	}
	childKey, err := DeriveChildKey(masterKey, path)
	if err != nil {
		t.Errorf("Failed to derive child key: %v", err)
	}
	acc1, err := DeriveChildKey(childKey, []uint32{0})
	if err != nil {
		t.Errorf("Failed to derive child key: %v", err)
	}
	acc1addr := CRCAddressFromPub(Scalar2Pub(acc1.Key))
	if acc1addr != metamaskAddress {
		t.Errorf("Expected %s, got %s", metamaskAddress, acc1addr)
	}

}

// These have been borrowed from the MetaMask test suite
const metamaskSeed = ` debris dizzy   just program just float decrease vacant alarm reduce speak stadium  `
const testSeed = `excuse jaguar brand minute opera aim next video police grant find piano`
const metamaskAddress = `0x0DCD5D886577d5081B0c52e242Ef29E70Be3E7bc`

func TestGetMnemonic(t *testing.T) {
	kf := new(Keyfile)
	kf.Plaintext = make([]byte, 32)

	rand.Read(kf.Plaintext)
	mnemonic, err := kf.GetPrivAsMnemonic()
	fmt.Println(mnemonic, err)

	mkey, err := bip39.MnemonicToByteArray(mnemonic, true)
	if err != nil {
		t.Errorf("Failed to create seed: %v", err)
	}
	t.Log(bytes.Equal(mkey, kf.Plaintext))
}

func TestFromMnemonic(t *testing.T) {
	m := testSeed // metamaskSeed
	NormalizeMnemonic(&m)
	derpath, _ := PathToUint32(EthPath)
	//derpath = append(derpath, 0)
	kf, eff := BIP32KeyFromMnemonic(m, "", "aaaaaa", derpath...)
	if eff != nil {
		t.Errorf("Failed to create keyfile: %v", eff)
	}
	fmt.Println(kf.Address)
}
