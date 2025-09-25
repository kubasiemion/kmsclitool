package common

import (
	"fmt"
	"testing"
)

func BenchmarkArgon1(b *testing.B) {
	b.ReportAllocs()
	ap := NewArgonParams()

	k := KeyFromPassArgon([]byte("jasio"), ap)
	fmt.Printf("0x%x\n", k)

	k2 := KeyFromPassArgon([]byte("jasio"), ap)
	fmt.Printf("0x%x\n", k2)
}
