package fcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func deriveKeyFromFile(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// 🔽 Using SHA256 of file content as "MFCC checksum"
	h := sha256.Sum256(data)
	return h[:], nil
}

func encrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, key[:block.BlockSize()])
	stream.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func decrypt(key []byte, data []byte) ([]byte, error) {
	return encrypt(key, data) // CTR decryption = encryption
}

func Echecksum(filePath, fromPath string, decryptFlag bool) {

	if filePath == "" || fromPath == "" {
		fmt.Println("Usage: go run main.go -file secret.txt -from basefile [-decrypt]")
		os.Exit(1)
	}

	key, err := deriveKeyFromFile(fromPath)
	if err != nil {
		panic(err)
	}

	input, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}

	var output []byte
	if decryptFlag {
		output, err = decrypt(key, input)
	} else {
		output, err = encrypt(key, input)
	}
	if err != nil {
		panic(err)
	}

	outFile := filePath + ".enc"
	if decryptFlag {
		outFile = strings.TrimSuffix(filePath, ".enc")
	}

	if err := ioutil.WriteFile(outFile, output, 0644); err != nil {
		panic(err)
	}

	fmt.Println("Done. Output written to", outFile)
}
