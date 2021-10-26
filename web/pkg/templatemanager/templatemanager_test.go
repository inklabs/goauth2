package templatemanager_test

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2/web/pkg/templatemanager"
)

//go:embed testdata
var testDataAssets embed.FS

func TestTemplateManager_RenderTemplate(t *testing.T) {
	templateAssets, templateErr := fs.Sub(testDataAssets, "testdata")
	require.NoError(t, templateErr)

	t.Run("succeeds", func(t *testing.T) {
		// Given
		var buf bytes.Buffer
		manager := templatemanager.New(templateAssets)

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
		manager := templatemanager.New(templateAssets)

		// When
		err := manager.RenderTemplate(&buf, "not-found.html", nil)

		// Then
		assert.Equal(t, templatemanager.TemplateNotFound, err)
	})

	t.Run("fails with io read error", func(t *testing.T) {
		// Given
		var buf bytes.Buffer
		manager := templatemanager.New(fileSystemWithFailingFileReader{})

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
		manager := templatemanager.New(templateAssets)

		// When
		err := manager.RenderTemplate(&buf, "invalid-hello.html", nil)

		// Then
		assert.Equal(t, templatemanager.MalformedTemplate, err)
	})
}

type fileSystemWithFailingFileReader struct{}

func (f fileSystemWithFailingFileReader) Open(_ string) (fs.File, error) {
	return failReader{}, nil
}

type failReader struct{}

func (w failReader) Close() error {
	return fmt.Errorf("failReader:Close")
}

func (w failReader) Seek(_ int64, _ int) (int64, error) {
	return 0, fmt.Errorf("failReader:Seek")
}

func (w failReader) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("failReader:Readdir")
}

func (w failReader) Stat() (os.FileInfo, error) {
	return nil, fmt.Errorf("failReader:Stat")
}

func (w failReader) Read(_ []byte) (n int, err error) {
	return 0, fmt.Errorf("failReader:Read")
	//	return 0, io.ErrShortBuffer
}
