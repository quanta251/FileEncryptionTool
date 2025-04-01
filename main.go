package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"os"
)
 
const aes_KEYSIZE = 32

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
  key := make([]byte, aes_KEYSIZE)
  _, err := rand.Read(key)
  if err != nil {
    log.Fatal("Could not generate a key:", err)
  }

  // Make the cipher block that will be used
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("Could not create aes.NewCipher object:", err)
	}

  // Make a buffer to store the ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

  // Generate the Initialization Vector (IV)
  iv := make([]byte, aes.BlockSize)
	// if _, err := io.ReadFull(rand.Reader, iv); err != nil {
  if _, err := rand.Read(iv); err != nil {
		log.Fatal("Could generate the IV:", err)
	}

  // Store the IV in the first part of the ciphertext
  copy(ciphertext, iv)
  fmt.Println("The ciphertext buffer just after copying the IV is:", ciphertext)

	// Create the Stream Cipher.
	stream := cipher.NewCTR(block, iv)
  stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	fmt.Println("ciphertext after encryption:", string(ciphertext))

  //-------------------------------------------------------------------------------
  //-------------------------------------------------------------------------------
  //-------------------------------------------------------------------------------

	plaintext2 := make([]byte, len(ciphertext) - aes.BlockSize)
  ciphertext2 := make([]byte, len(ciphertext))
  iv2 := make([]byte, aes.BlockSize)

  // copy the ciphertext into the new buffer
  copy(ciphertext2, ciphertext)

  // Read the IV from the first part of the ciphertext
  iv2 = ciphertext2[:aes.BlockSize]

  block2, err := aes.NewCipher(key)
  if err != nil {
    log.Fatal("Could not create the second cipher block:", err)
  }

  stream2 := cipher.NewCTR(block2, iv2)

  stream2.XORKeyStream(plaintext2, ciphertext2[aes.BlockSize:])

  fmt.Println("The decrypted plaintext is:", string(plaintext2), "\n\n\n")
  fmt.Println("----------------------------------")
  fmt.Println("Program finished")
  fmt.Println("----------------------------------")
}
