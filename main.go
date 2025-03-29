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
	filepath := "./myfile.txt"
	plaintext := getData(filepath)
	fmt.Println("plaintext:", string(plaintext))

	// Establish a key to use
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	fmt.Println("The key is now:", key)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("Could not create aes.NewCipher object:", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal("Could generate the IV:", err)
	}

	// Create the Stream Cipher.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	fmt.Println("ciphertext:", string(ciphertext))

	plaintext2 := make([]byte, len(ciphertext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext)

	fmt.Println("The ciphertext generated is:", string(ciphertext))
	fmt.Println("The plaintext generated is:", string(plaintext2))

}
