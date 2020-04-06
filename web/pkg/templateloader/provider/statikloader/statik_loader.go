package statikloader

import (
	"fmt"
	"io"

	"github.com/rakyll/statik/fs"

	"github.com/inklabs/goauth2/web/pkg/templatemanager"
)

type statikLoader struct{}

//New constructs a statik template loader
func New() *statikLoader {
	return &statikLoader{}
}

func (s *statikLoader) Load(templateName string) (io.Reader, error) {
	statikFS, _ := fs.New()
	file, err := statikFS.Open(fmt.Sprintf("/%s", templateName))
	if err != nil {
		return nil, templatemanager.TemplateNotFound
	}

	return file, nil
}
