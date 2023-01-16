package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
)

var RootIV = []byte{1, 2, 3, 4, 5, 6, 7, 8}

// 填充字符串（末尾）
func PaddingText(str []byte, blockSize int) []byte {
	//需要填充的数据长度
	paddingCount := blockSize - len(str)%blockSize
	//填充数据为：paddingCount ,填充的值为：paddingCount
	paddingStr := bytes.Repeat([]byte{byte(paddingCount)}, paddingCount)
	newPaddingStr := append(str, paddingStr...)
	//fmt.Println(newPaddingStr)
	return newPaddingStr
}

// 去掉字符（末尾）
func UnPaddingText(str []byte) []byte {
	n := len(str)
	count := int(str[n-1])
	newPaddingText := str[:n-count]
	return newPaddingText
}

// ---------------DES加密  解密--------------------
func DESEncrypt(src, key []byte) []byte {
	//1、创建并返回一个使用DES算法的cipher.Block接口
	block, _ := des.NewCipher(key)
	//2、对数据进行填充
	src1 := PaddingText(src, block.BlockSize())

	//3.创建一个密码分组为链接模式，底层使用des加密的blockmode接口
	blockMode := cipher.NewCBCEncrypter(block, RootIV)
	//4加密连续的数据块
	desc := make([]byte, len(src1))
	blockMode.CryptBlocks(desc, src1)
	return desc
}
func DESDecrypt(src, key []byte) []byte {
	//创建一个block的接口
	block, _ := des.NewCipher(key)
	//链接模式，创建blockMode接口
	blockeMode := cipher.NewCBCDecrypter(block, RootIV)
	//解密
	blockeMode.CryptBlocks(src, src)
	//去掉填充
	newText := UnPaddingText(src)
	return newText
}
