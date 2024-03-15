package common

import (
	"bytes"
	"compress/gzip"
	"fmt"

	"compress/flate"
)

func GzipData(data []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func GunzipData(data []byte) ([]byte, error) {
	b := bytes.NewReader(data)
	gz, err := gzip.NewReader(b)
	if err != nil {
		return nil, err
	}
	var res bytes.Buffer
	_, err = res.ReadFrom(gz)
	if err != nil {
		return nil, err
	}
	return res.Bytes(), nil
}

// Should be a constant
var FlateHeader = []byte{0xF1, 0xA7, 0xE0}

func FlateData(data []byte) ([]byte, error) {
	//use flate instead of gzip
	var b bytes.Buffer
	b.Write(FlateHeader)
	flt, err := flate.NewWriter(&b, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := flt.Write(data); err != nil {
		return nil, err
	}
	if err := flt.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func UnflateData(data []byte) ([]byte, error) {

	if !bytes.Equal(data[:3], FlateHeader) {
		return nil, fmt.Errorf("no Flate header found: %x", data[:3])
	}
	b := bytes.NewReader(data[3:])
	flt := flate.NewReader(b)
	var res bytes.Buffer
	_, err := res.ReadFrom(flt)
	if err != nil {
		return nil, err
	}
	return res.Bytes(), nil
}
