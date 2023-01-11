package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"time"
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// AesEncrypt 加密函数
func aesEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	timeByte := fillTime(plaintext)

	blockSize := block.BlockSize()
	timeByte = PKCS5Padding(timeByte, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(timeByte))
	blockMode.CryptBlocks(crypted, timeByte)
	return crypted, nil
}

func fillTime(plaintext []byte) []byte {
	timeByte := make([]byte, len(plaintext)+4)
	curHour := (time.Now().Unix() - 1514736000) / 3600
	byte0 := byte(curHour & 0xFF)
	timeByte[0] = byte0
	byte1 := byte((curHour & 0xFF00) >> 8)
	timeByte[1] = byte1
	byte2 := byte((curHour & 0xFF0000) >> 16)
	timeByte[2] = byte2
	byte3 := byte((curHour & 0xFF) >> 24)
	timeByte[3] = byte3

	copy(timeByte[4:], plaintext)
	return timeByte
}

func AesEncrypt(plaintext []byte, key string) ([]byte, error) {
	return aesEncrypt(plaintext, covertUserKey(key))
}

func covertUserKey(secret string) []byte {
	key := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = secret[i] & 0xFF
	}
	return key
}

// AesDecrypt 解密函数
func AesDecrypt(ciphertext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(origData, ciphertext)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}
