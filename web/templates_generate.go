// +build dev

package web

import (
	"net/http"
)

//TemplateAssets contains project assets.
var TemplateAssets http.FileSystem = http.Dir("./templates")
