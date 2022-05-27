package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

func EncryptAES(kf *Keyfile, plaintext []byte, password []byte) error {
	//Handle KDF

	salt := make([]byte, 16)
	rand.Read(salt)
	/*
		kf.Crypto.KdfparamsPack.Dklen=32
		kf.Crypto.KdfparamsPack.N=131072
		kf.Crypto.KdfparamsPack.P=1
		kf.Crypto.KdfparamsPack.R=8
		kf.Crypto.KdfparamsPack.Salt=hex.EncodeToString(salt)
	*/
	switch kf.Crypto.Kdf {
	case "scrypt":
		kf.Crypto.KdfScryptParams.Dklen = 32
		kf.Crypto.KdfScryptParams.N = 131072
		kf.Crypto.KdfScryptParams.P = 1
		kf.Crypto.KdfScryptParams.R = 8
		kf.Crypto.KdfScryptParams.Salt = hex.EncodeToString(salt)
	default:
		return fmt.Errorf("Unsupported KDF scheme")

	}

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

	parambytes, err := json.Marshal(&kf.Crypto.KdfScryptParams)
	return kf.Crypto.KdfparamsPack.UnmarshalJSON(parambytes)
}

func DecryptKeyFile(kf *Keyfile, pass string) error {
	key, e := KeyFromPassScrypt([]byte("kaczuszka"), kf.Crypto.KdfScryptParams)
	if e != nil {
		return e
	}
	kf.Plaintext, e = Decrypt(kf, key)
	if e != nil {
		return e
	}
	return nil
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

func CRCAddressString(addr []byte) (adstr string) {
	adstr = "0x"
	l := len(addr)
	if l == 0 {
		return "0x"
	}

	var adr20 []byte
	if l > 20 {
		adr20 = addr[:20]
	} else {
		adr20 = make([]byte, 20)
		copy(adr20[20-l:], addr)

	}

	lowstrbytes := []byte(hex.EncodeToString(adr20))
	hashstring := addrKecc(adr20)

	for i := 0; i < 40; i++ {
		if lowstrbytes[i] < 58 { // a digit
			continue
		}

		if hashstring[i] > 0x37 {
			lowstrbytes[i] -= 32
		}
	}
	adstr += string(lowstrbytes)

	return
}

func addrKecc(addr []byte) string {
	b := Keccak256([]byte(hex.EncodeToString(addr)))
	return hex.EncodeToString(b)
}
