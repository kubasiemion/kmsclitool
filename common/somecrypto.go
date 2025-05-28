package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
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
	var key []byte
	var err error
	var scryptparams interface{}
	switch kf.Crypto.Kdf {
	case "scrypt":

		kf.Crypto.KdfScryptParams = *StdScryptParams()
		kf.Crypto.KdfScryptParams.Salt = hex.EncodeToString(salt)
		key, err = KeyFromPassScrypt(password, kf.Crypto.KdfScryptParams)
		if err != nil {
			return err
		}
		scryptparams = &kf.Crypto.KdfScryptParams

	case "pbkdf2":

		kf.Crypto.KdfPbkdf2params = *StdPbkdf2Params()
		kf.Crypto.KdfPbkdf2params.Salt = hex.EncodeToString(salt)
		key, err = KeyFromPassPbkdf2(password, kf.Crypto.KdfPbkdf2params)
		if err != nil {
			return err
		}
		scryptparams = &kf.Crypto.KdfPbkdf2params
	default:
		return fmt.Errorf("Unsupported KDF scheme: %s", kf.Crypto.Kdf)

	}

	//Letsencrypt
	var iv []byte
	ivlen := 16

	var flavour = "ctr" //default; crt or gcm
	var aeskeylen int
	switch strings.ToLower(kf.Crypto.Cipher) {
	case "aes-128-ctr":
		aeskeylen = 16
	case "aes-128-gcm":
		aeskeylen = 16
		flavour = "gcm"
		ivlen = 12
	case "aes-256-ctr":
		aeskeylen = 32
	case "aes-256-gcm":
		aeskeylen = 32
		flavour = "gcm"
		ivlen = 12
	default:
		return fmt.Errorf("Unsupported encryption: %s", kf.Crypto.Cipher)
	}

	iv = make([]byte, ivlen)
	rand.Read(iv)

	block, err := aes.NewCipher(key[0:aeskeylen])
	if err != nil {
		return err
	}
	ciphertext := make([]byte, len(plaintext))

	switch flavour {
	case "ctr":
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(ciphertext, plaintext)
	case "gcm":
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("error creating GCM: %v", err)
		}
		ciphertext = aesgcm.Seal(nil, iv, plaintext, nil)

	}
	kf.Crypto.Cipherparams.Iv = hex.EncodeToString(iv)
	kf.Crypto.Ciphertext = hex.EncodeToString(ciphertext)

	mac := Keccak256(append(key[16:], ciphertext...))
	kf.Crypto.Mac = hex.EncodeToString(mac)
	kf.Version = 3
	//_, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), ethkey)
	//pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)
	parambytes, err := json.Marshal(scryptparams)
	if err != nil {
		return err
	}
	return kf.Crypto.KdfparamsPack.UnmarshalJSON(parambytes)
}

func Decrypt(kf *Keyfile, key []byte) (plaintext []byte, err error) {
	switch strings.ToLower(kf.Crypto.Cipher) {
	case "aes-128-ctr":
		plaintext, err = DecryptAESCTR(kf, key[:16])
	case "aes-256-ctr":
		plaintext, err = DecryptAESCTR(kf, key)
	case "aes-128-gcm":
		plaintext, err = DecryptAESGCM(kf, key[:16])
	case "aes-256-gcm":
		plaintext, err = DecryptAESGCM(kf, key)
	default:
		err = fmt.Errorf("Not implemented cipher: %s\n", kf.Crypto.Cipher)
		return
	}
	return
}

func DecryptAESGCM(kf *Keyfile, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	iv, err := hex.DecodeString(kf.Crypto.Cipherparams.Iv)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	citx, err := hex.DecodeString(kf.Crypto.Ciphertext)
	if err != nil {
		return
	}
	plaintext, err = aesgcm.Open(nil, iv, citx, nil)
	return
}

func DecryptAESCTR(kf *Keyfile, key []byte) (privkey []byte, err error) {

	block, err := aes.NewCipher(key)
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

func Scalar2Pub(ethkey []byte) (pubkeyeth []byte) {
	x, y := secp256k1.S256().ScalarBaseMult(ethkey)
	pubkeyeth = append(x.Bytes(), y.Bytes()...)
	//fmt.Printf("Public key: %s\n", hex.EncodeToString(pubkeyeth))
	return
}

func CRCAddressFromPub(pubkeyeth []byte) string {
	return CRCAddressString(AddressFromPub(pubkeyeth))
}

func AddressFromPub(pubkeyeth []byte) []byte {
	kecc := Keccak256(pubkeyeth)
	return kecc[12:]
}

type vanityResult struct {
	key   []byte
	addr  string
	err   error
	tries int
}

func GenerateVanityKey(vanity string, caseSensitive bool, done *bool) vanityResult {
	i := 1
	key := make([]byte, 32)
	var addr string
	rand.Read(key)
	if len(vanity) > 0 {
		var af func(k []byte) (a string)
		if !caseSensitive {
			vanity = strings.ToLower(vanity)
			af = func(k []byte) string {
				a := hex.EncodeToString(AddressFromPub(Scalar2Pub(k)))
				return a
			}
		} else {
			af = func(k []byte) string { a := CRCAddressFromPub(Scalar2Pub(key)); return a[2:] }
		}
		rx, err := regexp.Compile(vanity)
		if err != nil {
			return vanityResult{err: err}
		}
		for len(rx.FindString(addr)) == 0 {
			if *done {
				return vanityResult{err: fmt.Errorf("Interrupted")}
			}
			i++

			for j := 0; j < 32; j++ {
				key[j]++
				if key[j] != 0 {
					break
				}
			}
			addr = af(key)
			//fmt.Println(a)
		}
	}
	return vanityResult{key, addr, nil, i}

}

func TimeConstraindedVanityKey(vanity string, caseSensitive bool, timeout int) ([]byte, string, error, int, time.Duration) {
	start := time.Now()
	result := make(chan vanityResult, 1)
	Workers := runtime.NumCPU()
	runtime.GOMAXPROCS(Workers)
	done := false
	for i := Workers; i > 0; i-- {
		go func() {
			result <- GenerateVanityKey(vanity, caseSensitive, &done)
		}()
	}
	select {
	case <-time.After(time.Duration(timeout) * time.Second):
		fmt.Println("Timeout")
		done = true
		return nil, "", fmt.Errorf("Timeout after %v seconds", timeout), 0, time.Since(start)
	case result := <-result:
		done = true
		return result.key, result.addr, nil, result.tries * runtime.NumCPU(), time.Since(start)
	}

}

func CalcCREATEAddress(address []byte, nonce uint) ([]byte, error) {
	if len(address) != 20 {
		return nil, fmt.Errorf("Wrong address length: %v", len(address))
	}
	//data, err := rlp.EncodeToBytes([]interface{}{address, nonce})
	data, err := rlp_encode([]interface{}{address, nonce})
	if err != nil {
		return nil, err
	}

	return Keccak256(data)[12:], nil

}

func CalcCREATE2Address(address, codehash, salt []byte) ([]byte, error) {
	if len(salt) != 32 {
		return nil, fmt.Errorf("Wrong salt length")
	}
	if len(address) != 20 {
		return nil, fmt.Errorf("Wrong address length: %v", len(address))
	}
	return Keccak256([]byte{0xff}, address, salt[:], codehash)[12:], nil

}

func ParseHexString(hexstring string) ([]byte, error) {
	if len(hexstring) > 1 {
		if hexstring[:2] == "0x" {
			hexstring = hexstring[2:]
		}
	}

	return hex.DecodeString(hexstring)
}

type KdfScryptparams struct {
	Dklen int    `json:"dklen"`
	Salt  string `json:"salt"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
}

type KdfPbkdf2params struct {
	C     int    `json:"c"`
	Dklen int    `json:"dklen"`
	Prf   string `json:"prf"`
	Salt  string `json:"salt"`
}

// function returning stadard scryp parameters as KdfScryptparams struct
func StdScryptParams() *KdfScryptparams {
	return &KdfScryptparams{Dklen: 32, N: 131072, P: 1, R: 8}
}

// function returning stadard pbkdf2 parameters as KdfPbkdf2params struct
func StdPbkdf2Params() *KdfPbkdf2params {
	return &KdfPbkdf2params{C: 262144, Dklen: 32, Prf: "hmac-sha256"}
}
