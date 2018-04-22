package wxcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrAppIdInvalid = errors.New("appid不匹配")
)

type WxCrypto struct {
	token  string
	appid  string
	aesKey []byte
	iv     []byte
}

// 实例化
func New(token, appid, encodingAESKey string) (*WxCrypto, error) {
	aesKey, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, err
	}
	return &WxCrypto{
		token:  token,
		appid:  appid,
		aesKey: aesKey,
		iv:     aesKey[:16],
	}, nil
}

// 加密 data为要加密的XML字符串转换后的字节数组
func (p *WxCrypto) Encrypt(data []byte) ([]byte, error) {
	var (
		random16  = make([]byte, 16)
		msgLength = int32(len(data))
		appid     = []byte(p.appid)
		err       error
	)
	// 写入随机数
	if _, err := io.ReadFull(rand.Reader, random16); err != nil {
		return nil, err
	}
	// 写入消息体
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, &random16)
	err = binary.Write(buf, binary.BigEndian, &msgLength)
	err = binary.Write(buf, binary.BigEndian, &data)
	err = binary.Write(buf, binary.BigEndian, &appid)
	if err != nil {
		return nil, err
	}
	data = buf.Bytes()
	data = PKCS7Encode(data, 32)
	// 开始加密
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, p.iv)
	cipherData := make([]byte, len(data))
	mode.CryptBlocks(cipherData, data)
	return cipherData, nil
}

// 解密 data为微信传输过来的XML消息体Encrypt字段base64解码后的字节数组
func (p *WxCrypto) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, p.iv)
	mode.CryptBlocks(data, data)
	data = PKCS7Decode(data)
	// 去除随机的16字节
	data = data[16:]
	// 解码消息
	var (
		msgLength int32
		reader    = bytes.NewReader(data)
	)
	err = binary.Read(reader, binary.BigEndian, &msgLength)
	msg := make([]byte, int(msgLength))
	err = binary.Read(reader, binary.BigEndian, &msg)
	appid := make([]byte, len(p.appid))
	err = binary.Read(reader, binary.BigEndian, &appid)
	if err != nil {
		return nil, err
	}
	if string(appid) != p.appid {
		return nil, ErrAppIdInvalid
	}
	return msg, nil
}
