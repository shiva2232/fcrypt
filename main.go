package main

import (
	"flag"
	"sssuaa/fcrypto"
)

func main() {
	filePath := flag.String("file", "", "file to encrypt/decrypt")
	fromPath := flag.String("from", "", "file used to generate checksum/MFCC key")
	decryptFlag := flag.Bool("decrypt", false, "set to true to decrypt")
	checksum := flag.Bool("c", false, "use checksum to encrypt/decrypt")
	flag.Parse()
	if *checksum {
		fcrypto.Echecksum(*filePath, *fromPath, *decryptFlag)
	} else {
		fcrypto.Eaudio(*filePath, *fromPath, *decryptFlag)
	}
}
