package livefilesystemloader_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2/web/pkg/templateloader/provider/livefilesystemloader"
	"github.com/inklabs/goauth2/web/pkg/templatemanager"
)

func TestLiveFileTemplate_Load(t *testing.T) {
	t.Run("loads template", func(t *testing.T) {
		// Given
		loader := livefilesystemloader.New("./testdata")

		// When
		templateReader, err := loader.Load("hello.html")

		// Then
		require.NoError(t, err)
		var buf bytes.Buffer
		_, err = buf.ReadFrom(templateReader)
		require.NoError(t, err)
		assert.Equal(t, "Hello, {{.Name}}!\n", buf.String())
	})

	t.Run("fails when template not found", func(t *testing.T) {
		loader := livefilesystemloader.New("./testdata")

		// When
		_, err := loader.Load("not-found.html")

		// Then
		assert.Equal(t, templatemanager.TemplateNotFound, err)
	})
}
