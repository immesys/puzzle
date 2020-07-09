package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
)

const KeySize = 16
const NonceLength = 16

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("usage: unlock <key>\n")
		fmt.Printf("(ciphertext is read from stdin)\n")
		os.Exit(1)
	}

	ciphertextB64, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Printf("error reading stdin: %v\n", err)
	}

	combinedCiphertext, err := base64.StdEncoding.DecodeString(string(ciphertextB64))
	if err != nil {
		fmt.Printf("could not decode stdin as base64: %v\n", err)
	}
	if len(combinedCiphertext) <= NonceLength {
		fmt.Printf("seems like your ciphertext is a bit short\n")
	}

	key, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil || len(key) != KeySize {
		fmt.Printf("doesn't seem like that key is valid\n")
		os.Exit(2)
	}

	nonce := combinedCiphertext[:NonceLength]
	ciphertext := combinedCiphertext[NonceLength:]

	cypher, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCMWithNonceSize(cypher, NonceLength)

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("nah, that did not work (%v)\n", err)
		os.Exit(5)
	}

	fmt.Printf("congratulations! the message was decrypted!\n%s\n", plaintext)
	os.Exit(0)
}
