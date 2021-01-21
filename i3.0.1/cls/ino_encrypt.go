package cls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"encoding/hex"
	"strings"

	"github.com/sigurn/crc16"
)

type UserInfo struct {
	iSid       int
	bMngYn     bool
	iSiteId    int
	bUseYn     bool
	sLoginId   string
	sFirstName string
	sLastName  string
	sUserEmail string
	iCurrency  int
}

var StdAlpabet string = "12345678abcdefghijklmnpqrstuvwxy"
var base *base32.Encoding = base32.NewEncoding(StdAlpabet)
var crcTable *crc16.Table = crc16.MakeTable(crc16.CRC16_ARC)

var aesKey []byte = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}
var aesIV []byte = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}

func EncryptAESCFB(src []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		Lprintf(1, "[ERR ] %s\n", err)
	}
	stream := cipher.NewCFB8Encrypter(block, aesIV)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(src, src)
	//fmt.Printf("(%v)", src)

	return src

}

func DecryptAESCFB(src []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		Lprintf(1, "[ERR ] %s\n", err)
	}
	stream := cipher.NewCFB8Decrypter(block, aesIV)
	stream.XORKeyStream(src, src)

	return src
}

func DDecrypt(src string) []byte {

	src = strings.TrimSpace(src)
	// add padding
	padding := "======="
	ipad := len(src) % 8
	Lprintf(4, "(%d) ipad  (%d)", len(src), ipad)
	if ipad != 0 {
		ipad = 8 - ipad
		src += padding[:ipad]
	}

	// decoding
	dest, err := base.DecodeString(src)
	if err != nil {
		Lprintf(4, "error decode (%s)", err)
		//dest[0] = 0x00 // 에러인 경우 []byte가 없으므로 panic 에러
		//return dest
		return nil
	}

	//Lprintf(4, "[INFO] decode start (%x)", dest)

	return DecryptAESCFB(dest)
}

func EEncode(src []byte) string {

	enc := EncryptAESCFB(src)

	// Lprintf(4, "[INFO] encrypt result  (%x)", enc)

	// encoding
	dest := base.EncodeToString(enc)

	// delete padding
	dest = strings.Trim(dest, "=")

	return dest
}

func Decode32(src string) []byte {

	// add padding
	padding := "======="
	ipad := len(src) % 8
	if ipad != 0 {
		ipad = 8 - ipad
		src += padding[:ipad]
	}

	// decoding
	dest, err := base.DecodeString(src)
	if err != nil {
		Lprintf(4, "error decode (%s)", err)
		dest[0] = 0x00
		return dest
	}

	Lprintf(4, "[INFO] decode start (%x)", dest)

	return dest
}

// hydradns vue ui client에서 사용하는 AES 256 대칭키 알고리즘
// Key
/*
var key string = "abcdefghijklmnopqrstuvxyz0123456"
var iv []byte = []byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36}
*/
// AES256 Encode
func Aes256Encrypt(plaintext string) string {
	//bKey := []byte(key)
	//bIV := iv
	bKey := aesKey
	bIV := aesIV
	bPlaintext := pkcs5Padding([]byte(plaintext), len(plaintext))

	block, _ := aes.NewCipher(bKey)
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	return hex.EncodeToString(ciphertext)
}

// 인코딩 뒤에 padding 채우는 함수
// 참고 : https://gist.github.com/yingray/57fdc3264b1927ef0f984b533d63abab
//        client에서 padding처리에 따라 padding 로직 수정 필요
func pkcs5Padding(ciphertext []byte, after int) []byte {
	mod := len(ciphertext) % aes.BlockSize
	var padtext []byte
	if (mod % aes.BlockSize) != 0 {
		//padding := (aes.BlockSize - len(ciphertext)%aes.BlockSize)
		padding := (aes.BlockSize - mod)
		padtext = bytes.Repeat([]byte{byte(0x20)}, padding) // client Aes256 소스에서 padding을 0x20으로 채움
	}

	return append(ciphertext, padtext...)
}

// AES256 Decode
func Aes256Decrypt(cipherText string) string {
	//bKey := hex.EncodeToString([]byte(key)) // return hexadecimal string
	//bIV := hex.EncodeToString(iv)           // return hexadecimal string
	bKey := hex.EncodeToString(aesKey) // return hexadecimal string
	bIV := hex.EncodeToString(aesIV)   // return hexadecimal string

	// 암호화된 데이터
	cipherTextDecoded, err := hex.DecodeString(cipherText) // returns the bytes represented by the hexadecimal string parameter
	if err != nil {
		Lprintf(1, "[ERR ] cipherTextDecoded : [", err, "]")
		return ""
	}
	// 대칭키 데이터
	encKeyDecoded, err := hex.DecodeString(bKey)
	if err != nil {
		Lprintf(1, "[ERR ] encKeyDecoded : [", err, "]")
		return ""
	}
	ivDecoded, err := hex.DecodeString(bIV)
	if err != nil {
		Lprintf(1, "[ERR ] bIV: [", err, "]")
		return ""
	}

	// 디코드 로직
	block, err := aes.NewCipher(encKeyDecoded)
	if err != nil {
		Lprintf(1, "[ERR ] encryptDecode: [", err, "]")
		return ""
	}

	mode := cipher.NewCBCDecrypter(block, ivDecoded)
	mode.CryptBlocks(cipherTextDecoded, cipherTextDecoded)

	return string(cipherTextDecoded)
}
