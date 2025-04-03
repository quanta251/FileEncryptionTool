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

func Encrypt() {
	// Get the filename from the command line
	var filename string = os.Args[2]

	// Make the key and generate random bytes
	key := make([]byte, aes_KEYSIZE)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalln("The key could not be generated:", err)
	}

	// Create the Initilization Vector (IV)
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		log.Fatalln("The IV could not be generated:", err)
	}

	// Create the ciphertext and plaintext buffers
	plainBuf := make([]byte, bufferSize)
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
		bytesRead, err := plaintextFile.Read(plainBuf)
		if err != nil {
			// End of file has been reached if this is triggered
			break
		}

		// Only want to encrypt UP TO the amount of data read from file. Hence, the [:bytesRead]
		stream.XORKeyStream(cipherBuf, plainBuf[:bytesRead])

		// Only want to write the bytes encrypted (up to [:bytesRead]), ignoring the rest of cipherBuf so we don't write leftover bytes.
		ciphertextFile.Write(cipherBuf[:bytesRead])
	}

	fmt.Println("File encrypted!")

}

func Decrypt() {
	var ciphertextPath string = os.Args[2]
	var keyPath string = os.Args[3]

	// Open the ciphertext, plaintext, and key file streams
	ciphertextFile, err := os.Open(ciphertextPath)
	if err != nil {
		log.Fatalln("Could not open the ciphertext file:", err)
	}
	defer ciphertextFile.Close()

	plaintextFile, err := os.Create(ciphertextPath + ".plain")
	if err != nil {
		log.Fatalln("Could not create a plaintext file:", err)
	}
	defer plaintextFile.Close()

	keyFile, err := os.Open(keyPath)
	if err != nil {
		log.Fatalln("Could not open the key file:", err)
	}
	defer keyFile.Close()

	// Make the key slice and store the key bytes in it
	key := make([]byte, aes_KEYSIZE)
	_, err = keyFile.Read(key)
	if err != nil {
		log.Fatalln("Could not read the key file:", err)
	}

	// Read the Initilization Vector from the start of the ciphertext file
	iv := make([]byte, aes.BlockSize)
	_, err = ciphertextFile.Read(iv)
	if err != nil {
		log.Fatalln("Could not read the Initilization Vector", err)
	}

	// Create the cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln("Could not create new cipher block", err)
	}

	// Create new cipher stream
	stream := cipher.NewCTR(block, iv)

	// Create the ciphertext and plaintext buffers to store temporarily while looping
	plainBuf := make([]byte, bufferSize)
	cipherBuf := make([]byte, bufferSize)

	// Loop over the ciphertext file stream until the end of file
	for {
		bytesRead, err := ciphertextFile.Read(cipherBuf)
		if err != nil {
			// End of file has been reached if this is triggered
			break
		}

		stream.XORKeyStream(plainBuf, cipherBuf[:bytesRead])

		_, err = plaintextFile.Write(plainBuf[:bytesRead])
		if err != nil {
			log.Fatalln("Could not write data to the plaintext file:", err)
		}
	}

}

func showHelp() {
	fmt.Print(
		"Usage: ./FileEncryptionTool [OPTIONS] <file-to-process> [key-file] \n\n",
		"  Options:\n",
		"\t'-d' or '--decrypt': Decrypt the file passed. If this option is chosen, then a key file should be passed to the program immediately after the data file.\n",
		"\t'-e' or '--encrypt': Encrypt the file passed. A key will be generated, and a file with the '.key' suffix will be created. Keep that a secret.\n",
	)
}

func main() {
	// show the help menu if requested
	for _, val := range os.Args {
		if val == "-h" || val == "--help" {
			showHelp()
		}
	}

	switch os.Args[1] {
	case "-d":
		Decrypt()
	case "-e":
		Encrypt()
	default:
		showHelp()
	}
}
