package wxcrypto

import (
	"encoding/base64"
	"testing"
)

var (
	msgText = "<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"
)

func TestWxCrypto(t *testing.T) {
	wx, err := New(
		"pamtest",
		"wxb11529c136998cb6",
		"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
	)
	if err != nil {
		t.Fatal(err)
	}
	// 加密
	cipherData, err := wx.Encrypt([]byte(msgText))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("加密后: %s", base64.StdEncoding.EncodeToString(cipherData))
	// 解密
	plainData, err := wx.Decrypt(cipherData)
	if err != nil {
		t.Fatal(err)
	}
	if string(plainData) != msgText {
		t.Fatal("解密明文错误")
	}
	t.Logf("解密后: %s", string(plainData))
}
