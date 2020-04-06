package livefilesystemloader

import (
	"fmt"
	"io"
	"os"

	"github.com/inklabs/goauth2/web/pkg/templateloader"
)

type liveFilesystemLoader struct {
	templatesPath string
}

//New constructs a live filesystem template loader. Every call to Load() will refresh from disk.
func New(templatesPath string) *liveFilesystemLoader {
	return &liveFilesystemLoader{
		templatesPath: templatesPath,
	}
}

func (f *liveFilesystemLoader) Load(templateName string) (io.Reader, error) {
	file, err := os.Open(fmt.Sprintf("%s/%s", f.templatesPath, templateName))
	if err != nil {
		return nil, templateloader.TemplateNotFound
	}

	return file, nil
}
