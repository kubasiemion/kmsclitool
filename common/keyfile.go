package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

var Verbose bool

type Keyfile struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Address string `json:"address,omitempty"`
	Crypto  struct {
		Ciphertext         string `json:"ciphertext"`
		ExtendedCiphertext string `json:"extendedciphertext,omitempty"`
		Cipherparams       struct {
			Iv string `json:"iv"`
		} `json:"cipherparams"`
		Cipher    string `json:"cipher"`
		Kdf       string `json:"kdf"`
		Kdfparams any    `json:"kdfparams"`
		Mac       string `json:"mac"`
	} `json:"crypto"`
	Plaintext []byte `json:"-"`
	PrivKey   []byte `json:"-"`
	ChainCode []byte `json:"-"`
	PubKey    string `json:"-"`
	Hint      string `json:"hint,omitempty"`
	Filename  string `json:"-"`
}

// Recoveres the encryption key from password
func KeyFromPassScrypt(password []byte, params ScryptParams) ([]byte, error) {
	salt, err := hex.DecodeString(params.Salt)
	if err != nil {
		return nil, err
	}
	return scrypt.Key(password, salt, params.N, params.R, params.P, params.Dklen)
}

// Recoveres the encryption key from password
func KeyFromPassPbkdf2(password []byte, params Pbkdf2Params) ([]byte, error) {
	salt, err := hex.DecodeString(params.Salt)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(password, salt, params.C, params.Dklen, sha256.New), nil

}

func KeyFromPassArgon(password []byte, params *ArgonParams) []byte {
	if len(params.Salt) == 0 {
		params.Salt = make([]byte, params.SaltLength)
		rand.Read(params.Salt)
	}
	key := argon2.IDKey(password, params.Salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return key
}

// Just a convenience wrapper copied from geth
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func (keyfile *Keyfile) VerifyMAC(key []byte) error {
	citx, err := hex.DecodeString(keyfile.Crypto.Ciphertext)
	if err != nil {
		return err
	}

	//verify mac
	mymac := hex.EncodeToString(Keccak256(append(key[16:32], citx...)))

	if mymac != keyfile.Crypto.Mac {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}

func (keyfile *Keyfile) KeyFromPass(pass []byte) (key []byte, err error) {
	switch keyfile.Crypto.Kdf {
	case KdfScrypt:
		params, ok := keyfile.Crypto.Kdfparams.(ScryptParams)
		if !ok {
			err = fmt.Errorf("Wrong script params")
			return
		}
		key, err = KeyFromPassScrypt(pass, params)
		if err != nil {
			return
		}

	case KdfPbkdf2:
		params, ok := keyfile.Crypto.Kdfparams.(Pbkdf2Params)
		if !ok {
			err = fmt.Errorf("Wrong script params")
			return
		}
		key, err = KeyFromPassPbkdf2(pass, params)
		if err != nil {
			return
		}
	case KdfArgon:
		params, ok := keyfile.Crypto.Kdfparams.(ArgonParams)
		if !ok {
			err = fmt.Errorf("Wrong script params")
			return
		}
		key = KeyFromPassArgon(pass, &params)
	default:
		err = fmt.Errorf("Unsupported KDF: %s", keyfile.Crypto.Kdf)
		return
	}
	return
}

func (kf *Keyfile) Decrypt(pass []byte) (err error) {
	key, err := kf.KeyFromPass(pass)
	if err != nil {
		return
	}
	fmt.Println("Verifying MAC...")
	err = kf.VerifyMAC(key)
	if err != nil {
		return
	}
	kf.Plaintext, err = Decrypt(kf, key)
	if strings.HasPrefix(kf.ID, BIP32) {
		bip32Key, err := bip32.Deserialize(kf.Plaintext)
		if err != nil {
			return err
		}
		kf.PrivKey = bip32Key.Key
		kf.ChainCode = bip32Key.ChainCode
	} else {
		kf.PrivKey = kf.Plaintext
	}

	return
}

func (kf *Keyfile) Serialize() (jsonbytes []byte, err error) {
	jsonbytes, err = json.MarshalIndent(kf, "", "  ")
	return
}

func (kf *Keyfile) Deserialize(jsonbytes []byte) (err error) {
	if kf == nil {
		kf = new(Keyfile)
	}
	err = json.Unmarshal(jsonbytes, kf)
	if err != nil {
		return
	}

	return
}

// Need to revive this function for external use
func GenerateAndWrapNewKey(pass []byte, kdf string, encalg string, priv []byte, vanity string, caseSensitive bool, timeout int) (kf *Keyfile, err error, tries int, span time.Duration) {
	kf = &Keyfile{}

	kf.Crypto.Kdf = kdf
	kf.Crypto.Cipher = strings.ToLower(encalg)
	kf.ID = NewUuid().String()
	ethkey := make([]byte, 32)
	if len(priv) > 1 {

		ethkey = Pad(priv, 32)

	} else {
		//Generate the Koblitz private key
		ethkey, _, tries, span, err = TimeConstraindedVanityKey(vanity, caseSensitive, timeout)
		if err != nil {
			return
		}
	}
	fmt.Println("here1")

	err = EncryptAES(kf, ethkey, pass, 1<<20)
	if err != nil {
		return
	}

	pubkeyeth := Scalar2Pub(ethkey)
	addr := CRCAddressFromPub(pubkeyeth)
	kf.PubKey = hex.EncodeToString(pubkeyeth)
	kf.Address = addr

	return
}

// Not exactly compliant with BIP39
func (kf *Keyfile) GetPrivAsMnemonic() (mnemonic string, err error) {
	if len(kf.Plaintext) == 0 {
		err = fmt.Errorf("No private key to convert to mnemonic")
		return
	}
	mnemonic, err = bip39.NewMnemonic(kf.Plaintext)

	return
}

func BIP32KeyFromMnemonic(mnemonic, password, keypass string, derpath ...uint32) (kf *Keyfile, err error) {

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, password)
	if err != nil {
		return
	}
	var masterKey *bip32.Key
	masterKey, err = bip32.NewMasterKey(seed)
	if err != nil {
		return
	}

	if len(derpath) > 0 {
		masterKey, err = DeriveChildKey(masterKey, derpath)
		if err != nil {
			return
		}
	}

	keyser, err := masterKey.Serialize()
	if err != nil {
		return
	}
	addr := CRCAddressFromPub(Scalar2Pub(masterKey.Key))
	kps := []string{}
	if len(keypass) > 0 {
		kps = append(kps, keypass)
	}

	kf, err = WrapSecret("", NewUuid().GetWithPattern(BIP32), keyser, "aes-128-ctr", KdfScrypt, addr, 0, kps...)
	if err != nil {
		return
	}
	return
}

const SplitAddress = "File contains a shard of a key"

func (kf *Keyfile) DisplayKeyFile(verbose bool) {

	if kf.Address == SplitAddress {
		id := "XX" + kf.ID[2:]

		fmt.Printf("%s from suite %s\n", SplitAddress, id)
		return
	}

	prv, pubkeyec := secp256k1.PrivKeyFromBytes(kf.PrivKey)
	pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)
	fmt.Printf("Public key: \t%s\n", hex.EncodeToString(pubkeyeth))
	if verbose {
		fmt.Printf("Private key: \t%s\n", hex.EncodeToString(kf.PrivKey))
		if len(kf.ChainCode) > 0 {
			fmt.Printf("Chain code: \t%s\n", hex.EncodeToString(kf.ChainCode))
		}
		fmt.Println("D:", prv.D)
		fmt.Println("X:", pubkeyec.X)
		fmt.Println("Y:", pubkeyec.Y)
	}
	kecc := Keccak256(pubkeyeth)
	addr := kecc[12:]
	fmt.Printf("ICAP: %s\n", ToICAP(addr))
	fmt.Printf("Ethereum addr: %s\n", CRCAddressString(addr))
	fmt.Printf("(in file: %s)\n", kf.Address)
	return
}

// ToICAP converts a 20-byte Ethereum address to an ICAP address using the "XE" country code.
func ToICAP(address []byte) string {
	if len(address) != 20 {
		return ""
	}

	// 1. Convert the 20-byte address to a big.Int
	addressInt := new(big.Int).SetBytes(address)

	// 2. Format the big.Int as a base-36 string.
	// The number is formatted to a 30-digit base-36 string.
	// This is the "basic bank account number" (BBAN) part of the ICAP.
	bban := strings.ToUpper(addressInt.Text(36))

	// Ensure the BBAN is 30 characters long by padding with leading zeros.
	bban = fmt.Sprintf("%030s", bban)

	// 3. Prepend country code and check digits placeholder.
	// "XE" is the non-standard country code.
	// "00" is a placeholder for the two check digits.
	iban := "XE00" + bban

	// 4. Calculate the checksum (MOD 97-10).
	// This involves rearranging the string and treating letters as numbers.
	// We move the first 4 characters to the end.
	ibanRearranged := iban[4:] + iban[:4]

	// 5. Convert letters to numbers (A=10, B=11, ..., Z=35).
	ibanNumbers := ""
	for _, r := range ibanRearranged {
		if r >= '0' && r <= '9' {
			ibanNumbers += string(r)
		} else {
			ibanNumbers += fmt.Sprintf("%d", r-'A'+10)
		}
	}

	// 6. Calculate the remainder after dividing by 97.
	ibanInt := new(big.Int)
	ibanInt.SetString(ibanNumbers, 10)
	remainder := new(big.Int)
	remainder.Mod(ibanInt, big.NewInt(97))

	// 7. Calculate the check digits.
	// checkDigits = 98 - remainder
	checkDigitsInt := new(big.Int).Sub(big.NewInt(98), remainder)
	checkDigits := fmt.Sprintf("%02s", checkDigitsInt.Text(10))

	// 8. Construct the final ICAP address.
	icapAddress := "XE" + checkDigits + bban
	return icapAddress
}

func FromICAP(icapAddress string) ([]byte, error) {
	icapAddress = strings.ToUpper(icapAddress)
	if !strings.HasPrefix(icapAddress, "XE") {
		return nil, fmt.Errorf("invalid ICAP address: must start with 'XE'")
	}

	// 1. Validate the ICAP address length. An ICAP address using the XE prefix
	// should be 34 characters long (2 for "XE", 2 for checksum, 30 for BBAN).
	if len(icapAddress) != 34 {
		return nil, fmt.Errorf("invalid ICAP address length: expected 34 characters, got %d", len(icapAddress))
	}

	// 2. Extract components: Country Code ("XE"), Check Digits, and BBAN.
	// We'll use the check digits and BBAN to validate the address.
	checkDigits := icapAddress[2:4]
	bban := icapAddress[4:]

	// 3. Perform the checksum validation using the MOD 97-10 algorithm.
	// We must reconstruct the IBAN with a placeholder for the check digits.
	iban := "XE00" + bban

	// Rearrange the string for the checksum calculation.
	ibanRearranged := iban[4:] + iban[:4]

	// Convert letters to numbers (A=10, B=11, ..., Z=35).
	ibanNumbers := ""
	for _, r := range ibanRearranged {
		if r >= '0' && r <= '9' {
			ibanNumbers += string(r)
		} else {
			ibanNumbers += fmt.Sprintf("%d", r-'A'+10)
		}
	}

	// Calculate the remainder after dividing by 97.
	ibanInt := new(big.Int)
	ibanInt.SetString(ibanNumbers, 10)
	remainder := new(big.Int)
	remainder.Mod(ibanInt, big.NewInt(97))

	// Calculate the expected check digits.
	expectedCheckDigitsInt := new(big.Int).Sub(big.NewInt(98), remainder)
	expectedCheckDigits := fmt.Sprintf("%02s", expectedCheckDigitsInt.Text(10))

	if checkDigits != expectedCheckDigits {
		return nil, fmt.Errorf("invalid ICAP checksum: expected %s, got %s", expectedCheckDigits, checkDigits)
	}

	// 4. Convert the base-36 BBAN back to a big.Int.
	addressInt := new(big.Int)
	addressInt.SetString(bban, 36)

	// 5. Convert the big.Int to a 20-byte slice.
	// Pad with leading zeros if necessary.
	addressBytes := addressInt.Bytes()
	if len(addressBytes) > 20 {
		return nil, fmt.Errorf("converted address is too long")
	}

	result := make([]byte, 20)
	copy(result[20-len(addressBytes):], addressBytes)

	return result, nil
}
