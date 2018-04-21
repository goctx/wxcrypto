package wxcrypto

// pkcs7解码
func pkcs7Decode(data []byte) []byte {
	pad := data[len(data)-1]
	if pad < 1 || pad > 32 {
		pad = 0
	}
	return data[:len(data)-int(pad)]
}
