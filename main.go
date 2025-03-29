package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
)

func getData(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("Could not open the file at:", path)
	}

	return data
}

func main() {
	const key_size = 32

	// Get the plaintext from the stored file.
	plaintext := getData("./myfile.txt")

	// Generate the key for this encryption
	key := make([]byte, key_size)
	check, err := rand.Read(key)
	if err != nil || check != key_size {
		log.Fatal("Something went wrong:", err)
	}

	// Create the cipher block that will be used to encrypt the plaintext
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	CipherBlock, err := aes.NewCipher(key)

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(CipherBlock, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	fmt.Println("The new ciphertext is:", string(ciphertext))

}
