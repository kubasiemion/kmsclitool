package common

/*
func TestRLP(t *testing.T) {
	address := make([]byte, 20)

	iterations := 100
	for i := 0; i < iterations; i++ {
		rand.Read(address)
		inonce, _ := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
		nonce := inonce.Uint64()
		gethrlpencoded, err := rlp.EncodeToBytes([]interface{}{address, nonce})
		if err != nil {
			t.Error(err)
		}
		rlpenc, err := rlp_encode([]interface{}{address, nonce})
		if err != nil {
			t.Error(err)
		}
		if string(gethrlpencoded) != string(rlpenc) {
			t.Error("RLP encoding error")
			t.Log(hex.EncodeToString(gethrlpencoded))
			t.Log(hex.EncodeToString(rlpenc))
		}
	}
}

*/
