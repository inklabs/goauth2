package goauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/inklabs/goauth2"
)

func Test_GeneratePasswordHash(t *testing.T) {
	// Given
	password := "test123!"

	// When
	hash := goauth2.GeneratePasswordHash(password)

	// Then
	isValid := goauth2.VerifyPassword(hash, password)
	assert.True(t, isValid)
}

func Test_VerifyPassword(t *testing.T) {
	// Given
	hash := "$2a$10$kXoIYjFFopkb5hGWTdFum.wuse7u8vyhq/5cJoyqbA9rI1cfR/ow6"
	password := "test123!"

	// When
	isValid := goauth2.VerifyPassword(hash, password)

	// Then
	assert.True(t, isValid)
}

func Test_VerifyPasswordFails(t *testing.T) {
	// Given
	hash := "$2a$10$kXoIYjFFopkb5hGWTdFum.wuse7u8vyhq/5cJoyqbA9rI1cfR/ow6"
	password := "wrong-password"

	// When
	isValid := goauth2.VerifyPassword(hash, password)

	// Then
	assert.False(t, isValid)
}
