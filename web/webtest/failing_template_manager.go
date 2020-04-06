package webtest

import (
	"fmt"
	"io"
)

type failingTemplateLoader struct{}

//NewFailingTemplateLoader constructs a failing template loader for test purposes
func NewFailingTemplateLoader() *failingTemplateLoader {
	return &failingTemplateLoader{}
}

func (f *failingTemplateLoader) Load(_ string) (io.Reader, error) {
	return nil, fmt.Errorf("failingTemplateManager.RenderTemplate")
}
