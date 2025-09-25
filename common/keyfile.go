package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	Address string `json:"address"`
	Crypto  struct {
		Ciphertext         string `json:"ciphertext"`
		ExtendedCiphertext string `json:"extendedciphertext,omitempty"`
		Cipherparams       struct {
			Iv string `json:"iv"`
		} `json:"cipherparams"`
		Cipher          string          `json:"cipher"`
		Kdf             string          `json:"kdf"`
		KdfparamsPack   json.RawMessage `json:"kdfparams,omitempty"`
		KdfScryptParams ScryptParams    `json:"-"`
		KdfPbkdf2params Pbkdf2Params    `json:"-"`
		ArgonParams     ArgonParams     `json:"-"`
		Mac             string          `json:"mac"`
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
	case "argon":
		key = KeyFromPassArgon(pass, &keyfile.Crypto.ArgonParams)
	default:
		err = fmt.Errorf("Unsupported KDF: " + keyfile.Crypto.Kdf)
		return
	}
	return
}

func (kf *Keyfile) UnmarshalKdfJSON() (err error) {

	switch kf.Crypto.Kdf {
	case "scrypt":
		ksp := new(ScryptParams)
		err = json.Unmarshal(kf.Crypto.KdfparamsPack, ksp)
		kf.Crypto.KdfScryptParams = *ksp
	case "pbkdf2":
		kpb := new(Pbkdf2Params)
		err = json.Unmarshal(kf.Crypto.KdfparamsPack, kpb)
		kf.Crypto.KdfPbkdf2params = *kpb
	case "argon":
		kap := new(ArgonParams)
		err = json.Unmarshal(kf.Crypto.KdfparamsPack, kap)
		kf.Crypto.ArgonParams = *kap

	}
	return err
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
	err = kf.UnmarshalKdfJSON()
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

	kf, err = WrapSecret("", NewUuid().GetWithPattern(BIP32), keyser, "aes-128-ctr", "scrypt", addr, 0, kps...)
	if err != nil {
		return
	}
	return
}
