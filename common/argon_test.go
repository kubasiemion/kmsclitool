package common

import (
	"fmt"
	"testing"
)

func BenchmarkArgon1(b *testing.B) {
	b.ReportAllocs()
	ap := NewArgonParams()

	k, _ := KeyFromPassArgon([]byte("jasio"), *ap)
	fmt.Printf("0x%x\n", k)

	k2, _ := KeyFromPassArgon([]byte("jasio"), *ap)
	fmt.Printf("0x%x\n", k2)
}

func TestArgon(t *testing.T) {
	kf := new(Keyfile)
	err := kf.UnmarshalJSON([]byte(argontestvector))
	if err != nil {
		t.Error(err)
	}
	if kf.Crypto.Kdf != KdfArgon {
		t.Errorf("Wrong kdf")
	}
	err = kf.Decrypt([]byte("aaaaaa"))
	if err != nil {
		t.Error(err)
	}
}

const argontestvector = `{"version":3,"id":"fa8a858a-d3a5-4f60-a365-c27d794a3240","crypto":{"ciphertext":"c32cf3369613ec6e54a63876bbf622606955788631d88c3f0cf6740f24b27f5f","cipherparams":{"iv":"c95b2c604d2a55b57f0ec510bc415b94"},"cipher":"aes-128-ctr","kdf":"argon","kdfparams":{"memory":1048576,"parallelism":4,"keylength":32,"iterations":3,"saltlength":16,"salt":"0x378fe315c4b221eaa0200c9149019254"},
"mac":"70f43821cf68fa05c11e79447a26119f97ae11bad081f88e07ee280d1fd14e60"}}`
