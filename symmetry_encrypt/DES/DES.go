package DES

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// DES加密代码
// src ->明文
// key ->密钥，8byte
func DesEncrypt_CBC(src, key []byte) []byte {
	//创建并返回一个使用DES算法的cipher.Block接口
	block, err := des.NewCipher(key)
	if err != nil {
		fmt.Println("加密接口创建失败！")
		panic(err)
	}

	//对最后一个明文分组进行数据填充
	src = PKCS5Padding(src, block.BlockSize())

	//创建一个密码分组为连接模式，底层使用DES加密的BlockMode接口
	//参数iv的长度，必须等于b的块尺寸
	tmp := []byte("helloAAA")
	blackMode := cipher.NewCBCEncrypter(block, tmp)

	//加密连续的数据块
	dst := make([]byte, len(src))
	blackMode.CryptBlocks(dst, src)

	fmt.Println("加密之后的数据：", dst)

	return dst
}

// DES解密代码
// src ->密文
// key ->密钥，与加密密钥相同
func DesDecrypt_CBC(src, key []byte) []byte {
	//创建并返回一个DES的cipher.Block接口
	block, err := des.NewCipher(key)
	if err != nil {
		fmt.Println("解密接口创建失败！")
		panic(err)
	}

	//创建一个密码分组为连接模式，底层使用DES解密的BlockMode接口
	tmp := []byte("helloAAA")
	blockMode := cipher.NewCBCDecrypter(block, tmp)

	//解密数据
	dst := src
	blockMode.CryptBlocks(src, dst)
	//去掉填充数据
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
