package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

func main() {

	//seed the random number generator for security
	seed := time.Now().UnixNano()
	rand.Seed(seed)

	nonce := make([]byte, 16)
	encryptionKey := make([]byte, 16)

	//read 4 random integers to fill up the IV
	for i := 0; i < 4; i++ {
		rv := rand.Uint32()
		binary.LittleEndian.PutUint32(nonce[i*4:], rv)
	}

	//also read 4 random integers to fill up the key
	for i := 0; i < 4; i++ {
		rv := rand.Uint32()
		binary.LittleEndian.PutUint32(encryptionKey[i*4:], rv)
	}

	//now encrypt the payload
	payload, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Printf("error reading stdin: %v\n", err)
	}

	cypher, _ := aes.NewCipher(encryptionKey)
	aead, _ := cipher.NewGCMWithNonceSize(cypher, len(nonce))

	//encrypt the payload with GCM
	ciphertext := aead.Seal(nil, nonce, payload, nil)

	//stick the real ciphertext and the nonce together
	combined := append(nonce, ciphertext...)

	fmt.Printf("your key is: %s\n", base64.StdEncoding.EncodeToString(encryptionKey))
	fmt.Printf("your ciphertext is: %s\n", base64.StdEncoding.EncodeToString(combined))
}
