package templatemanager_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2/web/pkg/templateloader/provider/livefilesystemloader"
	"github.com/inklabs/goauth2/web/pkg/templatemanager"
)

func TestTemplateManager_RenderTemplate(t *testing.T) {
	t.Run("succeeds", func(t *testing.T) {
		// Given
		var buf bytes.Buffer
		manager := templatemanager.New(
			livefilesystemloader.New("./testdata"),
		)

		// When
		err := manager.RenderTemplate(&buf, "hello.html", struct {
			Name string
		}{
			Name: "World",
		})

		// Then
		require.NoError(t, err)
		assert.Equal(t, "Hello, World!\n", buf.String())
	})

	t.Run("fails with template not found", func(t *testing.T) {
		// Given
		var buf bytes.Buffer
		manager := templatemanager.New(
			livefilesystemloader.New("./testdata"),
		)

		// When
		err := manager.RenderTemplate(&buf, "not-found.html", nil)

		// Then
		assert.Equal(t, templatemanager.TemplateNotFound, err)
	})

	t.Run("fails with io read error", func(t *testing.T) {
		// Given
		var buf bytes.Buffer
		manager := templatemanager.New(failLoader{})

		// When
		err := manager.RenderTemplate(&buf, "hello.html", struct {
			Name string
		}{
			Name: "World",
		})

		// Then
		assert.Equal(t, templatemanager.IOReadError, err)
	})

	t.Run("fails with invalid template", func(t *testing.T) {
		// Given
		var buf bytes.Buffer
		manager := templatemanager.New(
			livefilesystemloader.New("./testdata"),
		)

		// When
		err := manager.RenderTemplate(&buf, "invalid-hello.html", nil)

		// Then
		assert.Equal(t, templatemanager.MalformedTemplate, err)
	})
}

type failLoader struct{}

func (f failLoader) Load(_ string) (io.Reader, error) {
	return failReader{}, nil
}

type failReader struct{}

func (w failReader) Read(_ []byte) (n int, err error) {
	return 0, io.ErrShortBuffer
}
