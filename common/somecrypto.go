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
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/tyler-smith/go-bip32"
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
		kf.Crypto.KdfScryptParams.Dklen = 32
		kf.Crypto.KdfScryptParams.N = 131072
		kf.Crypto.KdfScryptParams.P = 1
		kf.Crypto.KdfScryptParams.R = 8
		kf.Crypto.KdfScryptParams.Salt = hex.EncodeToString(salt)
		key, err = KeyFromPassScrypt(password, kf.Crypto.KdfScryptParams)
		if err != nil {
			return err
		}
		scryptparams = &kf.Crypto.KdfScryptParams
	case "pbkdf2":
		kf.Crypto.KdfPbkdf2params.C = 262144
		kf.Crypto.KdfPbkdf2params.Dklen = 32
		kf.Crypto.KdfPbkdf2params.Prf = "hmac-sha256"
		kf.Crypto.KdfPbkdf2params.Salt = hex.EncodeToString(salt)
		key, err = KeyFromPassPbkdf2(password, kf.Crypto.KdfPbkdf2params)
		if err != nil {
			return err
		}
		scryptparams = &kf.Crypto.KdfPbkdf2params
	default:
		return fmt.Errorf("Unsupported KDF scheme")

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
	err   error
	tries int
}

func GenerateVanityKey(vanity string, caseSensitive bool) vanityResult {
	i := 1
	key := make([]byte, 32)
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
		for len(rx.FindString(af(key))) == 0 {
			i++
			rand.Read(key)

			//fmt.Println(a)
		}
	}

	return vanityResult{key, nil, i}
}

func TimeConstraindedVanityKey(vanity string, caseSensitive bool, timeout int) ([]byte, error, int, time.Duration) {
	start := time.Now()
	result := make(chan vanityResult, 1)
	Workers := runtime.NumCPU()
	runtime.GOMAXPROCS(Workers)

	for i := Workers; i > 0; i-- {
		go func() {
			result <- GenerateVanityKey(vanity, caseSensitive)
		}()
	}

	select {
	case <-time.After(time.Duration(timeout) * time.Second):
		return nil, fmt.Errorf("Timeout after %v seconds", timeout), 0, time.Since(start)
	case result := <-result:
		return result.key, nil, result.tries * runtime.NumCPU(), time.Since(start)
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

func CalcCREATE2Address(address, codehash, salt []byte, nonce uint) ([]byte, error) {
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

// Translate bop32 path to uint32 array
func PathToUint32(path string) ([]uint32, error) {
	var patharr []uint32
	steps := childfinder.FindAllString(path, -1)

	for _, step := range steps {
		var offset uint32 = 0x00000000
		if step[len(step)-1] == '\'' {
			step = step[:len(step)-1]
			offset = 0x80000000
		}
		i, err := strconv.ParseUint(step, 16, 32)
		if err != nil {
			return nil, err
		}
		patharr = append(patharr, uint32(i)+offset)
	}
	return patharr, nil
}
