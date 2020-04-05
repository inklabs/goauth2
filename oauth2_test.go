package goauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/inklabs/goauth2"
)

func TestInitialMethod(t *testing.T) {
	// Given

	// When
	actual := goauth2.InitialMethod()

	// Then
	assert.Equal(t, true, actual)
}
