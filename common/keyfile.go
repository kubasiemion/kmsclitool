package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
		Ciphertext   string `json:"ciphertext"`
		Cipherparams struct {
			Iv string `json:"iv"`
		} `json:"cipherparams"`
		Cipher          string          `json:"cipher"`
		Kdf             string          `json:"kdf"`
		KdfparamsPack   json.RawMessage `json:"kdfparams,omitempty"`
		KdfScryptParams KdfScryptparams `json:"-"`
		KdfPbkdf2params KdfPbkdf2params `json:"-"`
		Mac             string          `json:"mac"`
	} `json:"crypto"`
	Plaintext []byte `json:"-"`
	PubKey    string `json:"-"`
	Hint      string `json:"hint,omitempty"`
	Filename  string `json:"-"`
}

// Recoveres the encryption key from password
func KeyFromPassScrypt(password []byte, params KdfScryptparams) ([]byte, error) {
	salt, err := hex.DecodeString(params.Salt)
	if err != nil {
		return nil, err
	}
	return scrypt.Key(password, salt, params.N, params.R, params.P, params.Dklen)
}

// Recoveres the encryption key from password
func KeyFromPassPbkdf2(password []byte, params KdfPbkdf2params) ([]byte, error) {
	salt, err := hex.DecodeString(params.Salt)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(password, salt, params.C, params.Dklen, sha256.New), nil

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
	default:
		err = fmt.Errorf("Unsupported KDF: " + keyfile.Crypto.Kdf)
		return
	}
	return
}

func (kf *Keyfile) UnmarshalKdfJSON() (err error) {

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
		ethkey, _, err, tries, span = TimeConstraindedVanityKey(vanity, caseSensitive, timeout)
		if err != nil {
			return
		}
	}

	err = EncryptAES(kf, ethkey, pass)
	if err != nil {
		return
	}

	pubkeyeth := Scalar2Pub(ethkey)
	addr := CRCAddressFromPub(pubkeyeth)
	kf.PubKey = hex.EncodeToString(pubkeyeth)
	kf.Address = addr

	return
}
