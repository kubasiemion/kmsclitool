package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func EncryptAES(kf *Keyfile, plaintext []byte, password []byte) error {
	key, err := KeyFromPassScrypt(password, kf.Crypto.KdfScryptParams)
	if err != nil {
		return err
	}
	//Letsencrypt
	iv := make([]byte, 16)
	rand.Read(iv)

	var aeskeylen int
	switch strings.ToLower(kf.Crypto.Cipher) {
	case "aes-128-ctr":
		aeskeylen = 16
	case "aes-256-ctr":
		aeskeylen = 32
	default:
		return fmt.Errorf("Unsupported encryption: %s", kf.Crypto.Cipher)
	}

	block, err := aes.NewCipher(key[0:aeskeylen])
	if err != nil {
		return err
	}
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	kf.Crypto.Cipherparams.Iv = hex.EncodeToString(iv)
	kf.Crypto.Ciphertext = hex.EncodeToString(ciphertext)

	mac := Keccak256(append(key[16:], ciphertext...))
	kf.Crypto.Mac = hex.EncodeToString(mac)
	kf.Version = 3
	//_, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), ethkey)
	//pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)

	xuuid, err := uuid.NewUUID()
	kf.ID = xuuid.String()
	parambytes, err := json.Marshal(&kf.Crypto.KdfScryptParams)
	return kf.Crypto.KdfparamsPack.UnmarshalJSON(parambytes)
}

func Decrypt(kf *Keyfile, key []byte) (plaintext []byte, err error) {
	switch strings.ToLower(kf.Crypto.Cipher) {
	case "aes-128-ctr":
		plaintext, err = DecryptAES(kf, key[:16])
	case "aes-256-ctr":
		plaintext, err = DecryptAES(kf, key)
	default:
		err = fmt.Errorf("Not implemented cipher: %s\n", kf.Crypto.Cipher)
		return
	}
	return
}

func DecryptAES(kf *Keyfile, key []byte) (privkey []byte, err error) {

	block, err := aes.NewCipher(key[0:16])
	if err != nil {
		return
	}
	iv, err := hex.DecodeString(kf.Crypto.Cipherparams.Iv)
	if err != nil {
		return
	}
	stream := cipher.NewCTR(block, iv)
	citx, err := hex.DecodeString(kf.Crypto.Ciphertext)
	if err != nil {
		return
	}
	privkey = make([]byte, len(citx))
	stream.XORKeyStream(privkey, citx)
	return

}
