package AES

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AES加密
func AESEncrypt(src, key []byte) []byte {
	//创建一个AES加密的块对象
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("加密接口错误！")
		panic(err)
	}

	//数据填充
	src = PKCS5Padding(src, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])

	//数据加密
	dst := src
	blockMode.CryptBlocks(dst, src)

	return dst
}

// AES解密
func AESDecrypt(src, key []byte) []byte {
	blcok, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("解密接口错误！")
		panic(err)
	}

	//创建分组连接模式
	blockMode := cipher.NewCBCDecrypter(blcok, key[:blcok.BlockSize()])

	//数据解密
	dst := src
	blockMode.CryptBlocks(dst, src)

	//删除填充
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
