package templateloader

import (
	"errors"
	"io"
)

//TemplateLoader is the interface that loads a template as an io.Reader.
type TemplateLoader interface {
	Load(templateName string) (io.Reader, error)
}

var TemplateNotFound = errors.New("template not found")
