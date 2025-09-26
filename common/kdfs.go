package common

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

type Kdf struct {
	Name   string `json:"kdf"`
	Params any    `json:"kdfparams"`
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
	Salt        []byte `json:"salt,omitempty"`
}

func NewArgonParams() *ArgonParams {
	ap := ArgonParams{1024 << 10, 4, 32, 3, 32, nil}
	return &ap
}
