package common

import "testing"

func TestUuid(t *testing.T) {
	t.Log("Testing uuid")
	Uuid := NewUuid()
	t.Log(Uuid.String())
	n := 3
	t.Log(Uuid.GetWithLeadingX(n))

	for i := 0; i < 12; i += 2 {
		t.Log(Uuid.NthUuidString(i, n))
	}
	t.Log(Uuid.String())
	t.Log(Uuid.GetWithPattern("BIP32"))

}
