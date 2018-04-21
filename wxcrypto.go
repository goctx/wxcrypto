package wxcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
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

// 计算消息体签名
func (p *WxCrypto) makeMsgSignature(timestamp, nonce, encryptMsg string) string {
	params := []string{timestamp, nonce, encryptMsg, p.token}
	sort.Strings(params)

	s := sha1.New()
	io.Copy(s, strings.NewReader(strings.Join(params, "")))
	return fmt.Sprintf("%x", s.Sum(nil))
}

// 加密数据
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
	err = binary.Write(buf, binary.LittleEndian, &random16)
	err = binary.Write(buf, binary.LittleEndian, &msgLength)
	err = binary.Write(buf, binary.LittleEndian, &data)
	err = binary.Write(buf, binary.LittleEndian, &appid)
	if err != nil {
		return nil, err
	}
	// 开始加密
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("消息体长度错误")
	}
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, p.iv)
	cipherData := make([]byte, len(data))
	mode.CryptBlocks(cipherData, buf.Bytes())
	return cipherData, nil
}

// 解密
func (p *WxCrypto) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, p.iv)
	mode.CryptBlocks(data, data)
	data = pkcs7Decode(data)
	// 去除随机的16字节
	data = data[16:]
	// 解码消息
	var (
		msgLength int32
		reader    = bytes.NewReader(data)
	)
	err = binary.Read(reader, binary.LittleEndian, &msgLength)
	msg := make([]byte, int(msgLength))
	err = binary.Read(reader, binary.LittleEndian, &msg)
	appid := make([]byte, 4)
	err = binary.Read(reader, binary.LittleEndian, &appid)
	if err != nil {
		return nil, err
	}
	if string(appid) != p.appid {
		return nil, ErrAppIdInvalid
	}
	return msg, nil
}
