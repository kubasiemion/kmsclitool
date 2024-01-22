package common

import (
	"fmt"
	"math/big"
)

//A method that is equivalent to go-ethereum/common/rlp.go:EncodeToBytes

/*
def rlp_encode(input):

	if isinstance(input,str):
	    if len(input) == 1 and ord(input) < 0x80:
	        return input
	    return encode_length(len(input), 0x80) + input
	elif isinstance(input, list):
	    output = ''
	    for item in input:
	        output += rlp_encode(item)
	    return encode_length(len(output), 0xc0) + output

def encode_length(L, offset):

	if L < 56:
	     return chr(L + offset)
	elif L < 256**8:
	     BL = to_binary(L)
	     return chr(len(BL) + offset + 55) + BL
	 raise Exception("input too long")

def to_binary(x):

	if x == 0:
	    return ''
	return to_binary(int(x / 256)) + chr(x % 256)
*/
func rlp_encode(input interface{}) ([]byte, error) {
	if input == nil {
		return []byte{0xc0}, nil
	}
	switch input.(type) {
	case uint:
		bu := new(big.Int).SetUint64(uint64(input.(uint)))
		bs := bu.Bytes()
		return rlp_encode(bs)

	case uint32:
		bu := new(big.Int).SetUint64(uint64(input.(uint32)))
		bs := bu.Bytes()
		return rlp_encode(bs)

	case uint64:

		bu := new(big.Int).SetUint64(uint64(input.(uint64)))
		bs := bu.Bytes()
		return rlp_encode(bs)
	case string:
		return rlp_encode([]byte(input.(string)))
	case []byte:
		binput := input.([]byte)
		if len(binput) == 1 && binput[0] < 0x80 {
			return binput, nil
		}
		return append(encode_length(len(binput), 0x80), binput...), nil
	case []interface{}:
		output := []byte{}
		for _, item := range input.([]interface{}) {
			encoded, err := rlp_encode(item)
			if err != nil {
				return nil, err
			}
			output = append(output, encoded...)
		}
		return append(encode_length(len(output), 0xc0), output...), nil
	default:
		return nil, fmt.Errorf("Unsupported type: %T", input)
	}
}

func encode_length(L int, offset int) []byte {
	if L < 56 {
		return []byte{byte(L + offset)}
	} else if L < 256^8 {
		BL := to_binary(L)
		return append([]byte{byte(len(BL) + offset + 55)}, BL...)
	}
	return nil
}

func to_binary(x int) []byte {
	if x == 0 {
		return []byte{}
	}
	return append(to_binary(int(x/256)), byte(x%256))
}
