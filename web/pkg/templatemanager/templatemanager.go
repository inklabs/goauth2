package templatemanager

import (
	"errors"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
)

//TemplateManager holds templates that can be rendered via the html/template package
type TemplateManager struct {
	templateLoader http.FileSystem
}

//New constructs a template manager.
func New(templateLoader http.FileSystem) *TemplateManager {
	return &TemplateManager{templateLoader: templateLoader}
}

func (t *TemplateManager) RenderTemplate(w io.Writer, templateName string, data interface{}) error {
	templateReader, err := t.templateLoader.Open(templateName)
	if err != nil {
		return TemplateNotFound
	}

	bytes, err := ioutil.ReadAll(templateReader)
	if err != nil {
		return IOReadError
	}

	tmpl, err := template.New("").Parse(string(bytes))
	if err != nil {
		return MalformedTemplate
	}

	return tmpl.Execute(w, data)
}

var TemplateNotFound = errors.New("template not found")
var IOReadError = errors.New("IO read error")
var MalformedTemplate = errors.New("malformed template")
