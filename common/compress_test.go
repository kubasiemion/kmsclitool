package common

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGzip(t *testing.T) {
	var data = []byte("Hello, World!")
	res, err := GzipData(data)
	if err != nil {
		t.Errorf("TestGzip failed")
	}
	fmt.Printf("GzipData returned: %x\n", res)

	res, err = GunzipData(res)
	if err != nil {
		t.Errorf("TestGzip failed")
	}
	fmt.Printf("GunzipData returned: %s\n", string(res))
}

func TestFlate(t *testing.T) {
	var data = []byte("Hello, World!")
	res, err := FlateData(data)
	if err != nil {
		t.Errorf("TestFlate failed")
	}
	fmt.Printf("FlateData returned: %x\n", res)

	res, err = UnflateData(res)
	if err != nil {
		t.Errorf("TestFlate failed %s", err)
	}
	if bytes.Equal(data, res) {
		fmt.Printf("UnflateData returned: %s\n", string(res))
	} else {
		t.Errorf("TestFlate failed")
	}
}
