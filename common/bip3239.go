package common

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

const EthPath = "m/44'/60'/0'/0/0"
const Bip32MasterPass = "Bitcoin seed"

func MasterKeyFromMnemonic(mnemonic string, passphrase string) (*bip32.Key, error) {
	NormalizeMnemonic(&mnemonic)
	split := strings.Split(mnemonic, " ")
	fmt.Println(split)
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, string(passphrase))
	if err != nil {
		return nil, err
	}
	return bip32.NewMasterKey(seed)
}

var wordSeeker = regexp.MustCompile(`[a-z]+`)

func NormalizeMnemonic(mnm *string) {
	wds := wordSeeker.FindAllString(*mnm, -1)
	normmnm := wds[0]
	for i := 1; i < len(wds); i++ {
		normmnm += " " + wds[i]

	}
	*mnm = normmnm
}

// Create bip32 key (root) from mnemonic with custom passphrase
func MasterKeyFromSeed(seed []byte, passphrase string) (*bip32.Key, error) {

	hmac := hmac.New(sha512.New, []byte(passphrase))
	_, err := hmac.Write(seed)
	if err != nil {
		return nil, err
	}
	intermediary := hmac.Sum(nil)

	// Split it into our key and chain code
	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	// Validate key
	if len(keyBytes) != 32 || bytes.Compare(keyBytes, secp256k1.S256().N.Bytes()) >= 0 {
		return nil, fmt.Errorf("Invalid key length")
	}

	// Create the key struct
	key := &bip32.Key{
		Version:     bip32.PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         keyBytes,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}

	return key, nil
}

// Create bip32 key (root) from eth key and additional entropy (chaincode)
func RootKeyFromKey(key, chainCode []byte) (*bip32.Key, error) {
	// Create the key struct
	rkey := &bip32.Key{
		Version:     bip32.PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         key,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}

	return rkey, nil
}

// Derive child key from parent key according to path (bip32)
func DeriveChildKey(key *bip32.Key, path []uint32) (*bip32.Key, error) {
	for _, i := range path {
		ckey, err := key.NewChildKey(i)
		if err != nil {
			return nil, err
		}
		key = ckey

	}
	return key, nil
}

var childfinder = regexp.MustCompile(`[0-9a-fA-F]+[']*`)

// Translate bip32 path to uint32 array
func PathToUint32(path string) ([]uint32, error) {
	var patharr []uint32
	steps := childfinder.FindAllString(path, -1)

	for _, step := range steps {
		var offset uint32 = 0x00000000
		if step[len(step)-1] == '\'' {
			step = step[:len(step)-1]
			offset = 0x80000000
		}
		i, err := strconv.ParseUint(step, 10, 32)
		if err != nil {
			return nil, err
		}
		patharr = append(patharr, uint32(i)+offset)
	}
	return patharr, nil
}

func SeedToMnemonic(seed []byte) (string, error) {
	return bip39.NewMnemonic(seed)
}
