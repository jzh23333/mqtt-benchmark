package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"time"
)

var RootAes = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
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
	aesKey := RootAes
	if len(key) > 0 {
		aesKey = covertUserKey(key)
	}
	return aesEncrypt(plaintext, aesKey)
}

func covertUserKey(secret string) []byte {
	key := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = secret[i] & 0xFF
	}
	return key
}

func AesDecrypt(ciphertext []byte, key string) ([]byte, error) {
	aesKey := RootAes
	if len(key) > 0 {
		aesKey = covertUserKey(key)
	}
	return aesDecrypt(ciphertext, aesKey)
}

// AesDecrypt 解密函数
func aesDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(origData, ciphertext)
	origData = PKCS5UnPadding(origData)
	return verifyAndRemoveTime(origData), nil
}

func verifyAndRemoveTime(ciphertext []byte) []byte {
	realByte := make([]byte, len(ciphertext)-4)
	var hours uint = 0
	if len(ciphertext) > 4 {
		hours += uint(ciphertext[3])
		hours <<= 8

		hours += uint(ciphertext[2])
		hours <<= 8

		hours += uint(ciphertext[1])
		hours <<= 8

		hours += uint(ciphertext[0])

		curHour := int((time.Now().Unix() - 1514736000) / 3600)
		if (uint(curHour) - hours) > 24 {
			return nil
		}

		copy(realByte, ciphertext[4:])
		return realByte
	}
	return nil
}
