package common

import (
	"fmt"

	"github.com/google/uuid"
)

type Uuid struct {
	root uuid.UUID
	seq  int32
}

func NewUuid() *Uuid {
	return &Uuid{uuid.New(), 0}
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
func (u *Uuid) GetPattern(n int) string {
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
