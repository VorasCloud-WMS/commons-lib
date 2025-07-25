package encryptvoras

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// padKey takes a key of any length and returns a valid AES key (16, 24, or 32 bytes)
// by hashing the input key with SHA-256 and then truncating to the nearest valid length
func padKey(key []byte) []byte {
	hasher := sha256.New()
	hasher.Write(key)
	hash := hasher.Sum(nil)

	// Use the first 16, 24, or 32 bytes of the hash
	// This ensures we always use a strong key of valid length
	keyLen := len(key)
	if keyLen <= 16 {
		return hash[:16] // AES-128
	} else if keyLen <= 24 {
		return hash[:24] // AES-192
	}
	return hash[:32] // AES-256
}

func Encrypt(key, value []byte) (string, error) {
	paddedKey := padKey(key)
	block, err := aes.NewCipher(paddedKey)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(value))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], value)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(key []byte, value string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}

	paddedKey := padKey(key)
	block, err := aes.NewCipher(paddedKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
