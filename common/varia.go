package common

func Pad(data []byte, length int) []byte {
	padded := make([]byte, length)
	copy(padded[length-len(data):], data)
	return padded
}
