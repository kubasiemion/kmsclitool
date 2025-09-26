package common

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

type Kdf struct {
	Name   string `json:"kdf"`
	Params any    `json:"kdfparams"`
}

func (kdf *Kdf) KeyFromPass(pass []byte) (key []byte, err error) {
	switch kdf.Name {
	case KdfScrypt:
		params, ok := kdf.Params.(ScryptParams)
		if !ok {
			err = fmt.Errorf("Wrong params for %s: %v", kdf.Name, kdf.Params)
			return
		}
		return KeyFromPassScrypt(pass, params)
	case KdfPbkdf2:
		params, ok := kdf.Params.(Pbkdf2Params)
		if !ok {
			err = fmt.Errorf("Wrong params for %s: %v", kdf.Name, kdf.Params)
			return
		}
		return KeyFromPassPbkdf2(pass, params)
	case KdfArgon:
		params, ok := kdf.Params.(ArgonParams)
		if !ok {
			err = fmt.Errorf("Wrong params for %s: %v", kdf.Name, kdf.Params)
			return
		}
		return KeyFromPassArgon(pass, params)
	default:
		err = fmt.Errorf("Unsupported kdf: %s", kdf.Name)
		return
	}

}

type ScryptParams struct {
	Dklen int    `json:"dklen"`
	Salt  string `json:"salt"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
}

type Pbkdf2Params struct {
	C     int    `json:"c"`
	Dklen int    `json:"dklen"`
	Prf   string `json:"prf"`
	Salt  string `json:"salt"`
}

const KdfScrypt = "scrypt"
const KdfPbkdf2 = "pbkdf2"
const KdfArgon = "argon"

// function returning stadard scryp parameters as KdfScrytime.Since(start)
func NewScryptParams(n int) *ScryptParams {
	if n == 0 {
		n = 1 << 20
	}
	return &ScryptParams{Dklen: 32, N: n, P: 1, R: 8}
}

// function returning stadard pbkdf2 parameters as KdfPbkdf2params struct
func NewPbkdf2Params(c int) *Pbkdf2Params {
	if c == 0 {
		c = 3 * 262144
	}
	return &Pbkdf2Params{C: c, Dklen: 32, Prf: "hmac-sha256"}
}

type ArgonParams struct {
	Memory      uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLength   uint32 `json:"keylength"`
	Iterations  uint32 `json:"iterations"`
	SaltLength  uint8  `json:"saltlength,omitempty"`
	Salt        string `json:"salt,omitempty"`
}

func (ap *ArgonParams) SetSalt(slen uint8) {
	ap.SaltLength = slen
	salt := make([]byte, slen)
	rand.Read(salt)
	ap.Salt = fmt.Sprintf("0x%x", salt)

}

func (ap *ArgonParams) GetSalt() []byte {
	s, err := hex.DecodeString(ap.Salt[2:])
	if err != nil {
		return nil
	}
	return s
}

func NewArgonParams() *ArgonParams {
	ap := ArgonParams{1024 << 10, 4, 32, 3, 32, ""}
	return &ap
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
	var hashf func() hash.Hash
	switch params.Prf {
	case "hmac-sha256":
		hashf = sha256.New
	}
	return pbkdf2.Key(hashf, string(password), salt, params.C, params.Dklen)

}

func KeyFromPassArgon(password []byte, params ArgonParams) ([]byte, error) {
	key := argon2.IDKey(password, params.GetSalt(), params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return key, nil
}
