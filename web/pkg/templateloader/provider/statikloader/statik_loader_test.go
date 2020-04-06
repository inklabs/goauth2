package statikloader_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2/web/pkg/templateloader/provider/statikloader"
	"github.com/inklabs/goauth2/web/pkg/templatemanager"
	_ "github.com/inklabs/goauth2/web/statik"
)

func TestStatikLoader_Load(t *testing.T) {
	t.Run("succeeds with login page", func(t *testing.T) {
		// Given
		loader := statikloader.New()

		// When
		reader, err := loader.Load("login.html")

		// Then
		require.NoError(t, err)
		var buf bytes.Buffer
		_, err = buf.ReadFrom(reader)
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "Login")
	})

	t.Run("fails when not found", func(t *testing.T) {
		// Given
		loader := statikloader.New()

		// When
		_, err := loader.Load("not-found.html")

		// Then
		assert.Equal(t, templatemanager.TemplateNotFound, err)
	})
}
