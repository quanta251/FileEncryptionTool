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
const bufferSize = 4096

func getData(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("Could not open the file at:", path)
	}

	return data
}

func main() {
  // Get the filename from the command line
  var filename string = os.Args[1]

  // Make the key and generate random bytes
  key := make([]byte, aes_KEYSIZE)
  _, err := rand.Read(key)
  if err != nil {
    log.Fatalln("The key could not be generated:", err)
  }

  // Create the Initilization Vectork (IV)
  iv := make([]byte, aes.BlockSize)
  _, err = rand.Read(iv) 
  if err != nil {
    log.Fatalln("The IV could not be generated:", err)
  }

  // Create the ciphertext and plaintext buffers
  plainBuf  := make([]byte, bufferSize)
  cipherBuf := make([]byte, bufferSize)

  // Open the plaintext file
  plaintextFile, err := os.Open(filename)
  if err != nil {
    log.Fatalln("Could not open the plaintext file:", err)
  }
  defer plaintextFile.Close()

  // Open the ciphertext file
  ciphertextFile, err := os.Create(filename + ".enc")
  if err != nil {
    log.Fatalln("Could not open the ciphertext file:", err)
  }
  defer ciphertextFile.Close()

  // Open a file to write the key then close it.
  keyFile, err := os.Create(filename + ".key")
  if err != nil {
    log.Fatalln("Could not create the key file:", err)
  }
  bytesWritten, err := keyFile.Write(key)
  if err != nil {
    log.Fatalln("Could not write to the key file:", err)
  }

  // Write the IV at the start of the ciphertext file
  bytesWritten, err = ciphertextFile.Write(iv)
  if err != nil {
    log.Fatalln("Could not write the IV to the ciphertext file", err)
  }
  _ = bytesWritten

  // Create the block cipher
  block, err := aes.NewCipher(key)
  if err != nil {
    log.Fatalln("Could not create new block cipher", err)
  }

  // Create a new stream cipher
  stream := cipher.NewCTR(block, iv)

  // Loop over the plaintext file, read into the plaintext buffer, encrypt into the ciphertext buffer, then
  // write to the ciphertext file
  for {
    size, err := plaintextFile.Read(plainBuf)
    if err != nil {
      break
    }

    // Only want to encrypt UP TO the amount of data read from file. Hence, the [:size]
    stream.XORKeyStream(cipherBuf, plainBuf[:size])

    // Only want to write the bytes encrypted (up to [:size]), ignoring the rest of cipherBuf so we don't write leftover bytes.
    ciphertextFile.Write(cipherBuf[:size])
  }

  fmt.Println("File encrypted!")
}
