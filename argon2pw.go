// Package argon2pw provides ability to generated salted Argon2 hashes ideal for secure password storage.
// Additionally, argon2pw includes a function for constant time password comparison to prevent constant timing attacks.
//
// Example:
// package main
// import "github.com/raja/argon2pw"
//
// func main() {
// 	// Generate a hashed password
// 	testPassword := `testPassword$x1w432b7^`
// 	hashedPassword, err := argon2pw.GenerateSaltedHash(testPassword)
// 	if err != nil {
// 		log.Panicf("Hash generated returned error: %v", err)
// 	}

// 	// Test correct password in constant time
// 	valid, err := argon2pw.CompareHashWithPassword(hashedPassword, testPassword)
// 	log.Printf("The password validity is %t against the hash", valid)

// 	// Test incorrect password in constant time
// 	valid, err = argon2pw.CompareHashWithPassword(hashedPassword, "badPass")
// 	log.Printf("The password validity is %t against the hash", valid)

// }
package argon2pw

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordType         = "argon2"
	maxSaltSize          = 16
	encodedSaltSize      = 24
	argon2KeySize        = 32
	encodedargon2KeySize = 44
	argon2Time           = 4
	argon2Threads        = 4
	argon2Memory         = 32 * 1024
)

func generateSalt() (s string, err error) {
	unencodedSalt := make([]byte, maxSaltSize)
	_, err = rand.Read(unencodedSalt)
	if err != nil {
		return s, err
	}
	return base64.StdEncoding.EncodeToString(unencodedSalt), nil
}

// GenerateSaltedHash takes a plaintext password and generates an argon2 hash
func GenerateSaltedHash(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("Password length cannot be 0")
	}
	salt, _ := generateSalt()
	unencodedPassword := argon2.Key([]byte(password), []byte(salt), argon2Time, argon2Memory, argon2Threads, argon2KeySize)
	encodedPassword := base64.StdEncoding.EncodeToString(unencodedPassword)
	hash := fmt.Sprintf("%s$%d$%d$%d$%d$%s$%s",
		passwordType, argon2Time, argon2Memory, argon2Threads, argon2KeySize, salt, encodedPassword)

	return hash, nil
}

// CompareHashWithPassword compares an argon2 hash against plaintext password
func CompareHashWithPassword(hash, password string) (bool, error) {
	if len(hash) == 0 || len(password) == 0 {
		return false, errors.New("Arguments cannot be zero length")
	}
	hashParts := strings.Split(hash, "$")
	time, _ := strconv.Atoi((hashParts[1]))
	memory, _ := strconv.Atoi(hashParts[2])
	threads, _ := strconv.Atoi(hashParts[3])
	keySize, _ := strconv.Atoi(hashParts[4])
	salt := []byte(hashParts[5])
	key, _ := base64.StdEncoding.DecodeString(hashParts[6])

	calculateddKey := argon2.Key([]byte(password), salt, uint32(time), uint32(memory), uint8(threads), uint32(keySize))
	if subtle.ConstantTimeCompare(key, calculateddKey) != 1 {
		return false, errors.New("Password did not match")
	}
	return true, nil
}
