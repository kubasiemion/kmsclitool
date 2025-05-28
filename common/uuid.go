package common

import (
	"fmt"

	"github.com/google/uuid"
)

const BIP32 = "BIP32"
const SHARE = "SHARE"

var reservedPrefixes = []string{BIP32, SHARE} // Reserved prefixes

type Uuid struct {
	root uuid.UUID
	seq  int32
}

func isPlain(id uuid.UUID) bool {
	if id == uuid.Nil {
		return false
	}
	for _, p := range reservedPrefixes {
		if id.String()[:len(p)] == p {
			return false
		}
	}
	return true
}

func NewUuid() *Uuid {
	uid := uuid.Nil
	for !isPlain(uid) {
		uid = uuid.New()
	}
	return &Uuid{uid, 0}
}

func (u *Uuid) String() string {
	return u.root.String()
}

func (u *Uuid) SetSeq(seq int) {
	u.seq = int32(seq)
}

func (u *Uuid) GetSeg() int {
	return int(u.seq)
}

func (u *Uuid) Next() string {
	ret := u.NthUuidString(int(u.seq), 4)
	u.seq++
	return ret
}

func (u *Uuid) NthUuidString(n int, nbytes int) string {
	prefix := make([]byte, nbytes)
	for i := range prefix {
		prefix[i] = byte(n % 256)
		n >>= 8

	}

	prefix = append(prefix, u.root[nbytes:]...)
	nu, _ := uuid.FromBytes(prefix)
	return nu.String()
}

// Returns a string with n leading X characters
func (u *Uuid) GetWithLeadingX(n int) string {
	if n > 8 {
		fmt.Println("Warning: GetPattern only supports up to 8 leading X characters")
		n = 8
	}
	n <<= 1
	s := u.String()
	b := []byte(s)
	for i := 0; i < n; i += 2 {
		b[i] = 'X'
		b[i+1] = 'X'

	}
	return string(b)
}

// Returns a string with n leading prefix characters
// The prefix must be plain ASCII
func (u *Uuid) GetWithPattern(pat string) string {
	if len(pat) > 8 {
		fmt.Println("Warning: GetWithPattern only supports up to 8 leading X characters")
		pat = pat[:8]
	}

	s := u.String()
	s = pat + s[len(pat):]
	return s
}
