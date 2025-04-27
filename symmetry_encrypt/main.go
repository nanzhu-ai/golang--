package main

import (
	"encoding/base64"
	"fmt"
	"golang--/symmetry_encrypt/DES"
)

func main() {
	key := []byte("11111111")
	result := DES.DesEncrypt_CBC([]byte("HELLO,WORLD!"), key)
	fmt.Println(base64.StdEncoding.EncodeToString(result))

	result = DES.DesDecrypt_CBC(result, key)
	fmt.Println("解密之后的数据:", string(result))
}
