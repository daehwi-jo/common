package cls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"fmt"
	"strings"
)

var StdAlpabet string = "12345678abcdefghijklmnpqrstuvwxy"
var base *base32.Encoding = base32.NewEncoding(StdAlpabet)

var aesKey []byte = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}
var aesIV []byte = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}

func EncryptAESCFB(src []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Printf("error \n")
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
		fmt.Printf("error \n")
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
		dest[0] = 0x00
		return dest
	}

	//Lprintf(4, "[INFO] decode start (%x)", dest)

	return DecryptAESCFB(dest)
}

func EEncode(src []byte) string {

	enc := EncryptAESCFB(src)

	//Lprintf(4, "[INFO] encrypt result  (%x)", enc)

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

/*
* CheckSum 데이터(4bytes)
* data : CheckSum 위한 원본 데이터
 */
func makeCheckSum(data []byte) (string, uint32) {
	var word16 uint16
	var sum uint32
	var result string

	Lprintf(4, "[INFO] checksum (%s)", string(data))
	dLen := len(data)

	// 모든 데이터를 덧셈
	for i := 0; i < dLen; i += 2 {
		word16 = (uint16(data[i]) << 8) & 0xFF00
		if (i + 1) < dLen {
			word16 += uint16(data[i+1]) & 0xFF
		}
		//fmt.Printf("[INFO] word16[%d] (%x) (%d)\n", i, word16, word16)
		sum += uint32(word16)
	}

	// 캐리 니블 버림
	sum = (sum & 0xFFFF) + (sum >> 16)
	// 2의 보수
	sum = ^sum
	result = fmt.Sprintf("%X", sum)
	return result[4:], sum
}
