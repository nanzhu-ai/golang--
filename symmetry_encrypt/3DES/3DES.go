package DES_3

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// 3DES加密函数
func TripleDESEncrypt(src, key []byte) []byte {
	//创建cipher.Block接口
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		fmt.Println("加密接口错误！")
		panic(err)
	}

	//明文填充
	src = PKCS5Padding(src, block.BlockSize())

	//创建一个密码分组连接，底层使用3DES加密的BlockMode模型
	blockMode := cipher.NewCBCEncrypter(block, key[:8])

	//加密数据
	dst := src
	blockMode.CryptBlocks(dst, src)
	return dst
}

// 3DES解密函数
func TripleDESDecrypt(src, key []byte) []byte {
	//创建Block接口
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		fmt.Println("解密接口错误！")
		panic(err)
	}

	//创建密码分组连接，底层使用BlockMode模型
	blockMode := cipher.NewCBCDecrypter(block, key[:8])

	//解密数据
	dst := src
	blockMode.CryptBlocks(dst, src)

	dst = PKCS5UnPadding(dst)

	return dst
}

// 填充函数
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	//计算最后一个分组缺少字节数
	padding := blockSize - (len(ciphertext) % blockSize)

	//创建填充切片，值为padding
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	//将填充切片添加到原始数据后面
	newText := append(ciphertext, padText...)

	return newText
}

// 删除填充数据函数
func PKCS5UnPadding(origData []byte) []byte {
	//计算数据长度
	length := len(origData)

	//获取填充字节数
	number := int(origData[length-1])

	//删除填充字节
	result := origData[:(length - number)]

	return result
}
