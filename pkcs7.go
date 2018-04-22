package wxcrypto

import "strings"

// PKCS#7解码
func PKCS7Decode(data []byte) []byte {
	pad := data[len(data)-1]
	if pad < 1 || pad > 32 {
		pad = 0
	}
	return data[:len(data)-int(pad)]
}

// PKCS#7填充
func PKCS7Encode(data []byte, blockSize int) []byte {
	// 计算需要填充的位数
	padSize := blockSize - (len(data) % blockSize)
	if padSize == 0 {
		padSize = blockSize
	}
	// 获得补位用的字符
	padChar := rune(padSize)
	padStr := strings.Repeat(string(padChar), padSize)
	return append(data, []byte(padStr)...)
}
