# argon2pw
[![GoDoc](https://godoc.org/github.com/raja/argon2pw?status.svg)](https://godoc.org/github.com/raja/argon2pw)

Argon2 password hashing library with constant time hash comparison


**Usage:**
```go
package main
 import "github.com/raja/argon2pw"

 func main() {
	 // Generate a hashed password
	 testPassword := `testPassword$x1w432b7^`
	 hashedPassword, err := argon2pw.GenerateSaltedHash(testPassword)
	 if err != nil {
         log.Panicf("Hash generated returned error: %v", err)
	 }

	 // Test correct password in constant time
	 valid, err := argon2pw.CompareHashWithPassword(hashedPassword, testPassword)
	 log.Printf("The password validity is %t against the hash", valid)

	 // Test incorrect password in constant time
	 valid, err = argon2pw.CompareHashWithPassword(hashedPassword, "badPass")
	 log.Printf("The password validity is %t against the hash", valid)
 }

```
