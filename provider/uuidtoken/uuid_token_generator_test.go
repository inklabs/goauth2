package uuidtoken_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2/provider/uuidtoken"
)

func Test_Generator_ReturnsHexTokenWithoutHyphens(t *testing.T) {
	// Given
	generator := uuidtoken.NewGenerator()

	// When
	token := generator.New()

	// Then
	assert.Equal(t, 32, len(token))
	assert.NotContains(t, token, "-")
}

func Test_Generator_ReturnsValidUUIDToken(t *testing.T) {
	// Given
	generator := uuidtoken.NewGenerator()

	// When
	token := generator.New()

	// Then
	u, err := uuid.Parse(token)
	require.NoError(t, err)
	actualWithoutHyphens := strings.Replace(u.String(), "-", "", -1)
	assert.Equal(t, token, actualWithoutHyphens)
}
