# 微信开放平台加解密实现

本库只实现`数据加解密`，XML解析和base64编码请自行实现

## 安装

```bash
go get github.com/goctx/wxcrypto
```

## 消息加密

```go
package main
import (
	"encoding/base64"
	"log"
	"github.com/goctx/wxcrypto"
)

func main()  {
 wx, err:=wxcrypto.New("token","appid","encodingAESKey")
 if err != nil {
    log.Fatal(err)
 }
 cipherData, err:=wx.Encrypt([]byte("<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"))
 if err != nil {
    log.Fatal("加密失败")
 }
 log.Printf("加密数据: %s", base64.StdEncoding.EncodeToString(cipherData))
}
```

## 消息解密

```go
package main
import (
	"encoding/base64"
	"log"
	"github.com/goctx/wxcrypto"
)

func main()  {
 wx, err:=wxcrypto.New("token","appid","encodingAESKey")
 if err != nil {
    log.Fatal(err)
 }
 var cipherData []byte // base64解码后到字节数组
 plainData, err:=wx.Encrypt(cipherData)
 if err != nil {
    log.Fatal("解密失败")
 }
 log.Printf("解密数据: %s", string(plainData))
}
```

## License

[MIT License](https://opensource.org/licenses/MIT)