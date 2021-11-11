package goauth2

import (
	"golang.org/x/crypto/bcrypt"
)

// GeneratePasswordHash returns a password using bcrypt.GenerateFromPassword.
func GeneratePasswordHash(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return string(hash)
}

// VerifyPassword verifies a password using bcrypt.CompareHashAndPassword.
func VerifyPassword(hash string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false
	}

	return true
}
