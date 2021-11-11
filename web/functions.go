package web

import (
	"html/template"
	"time"

	"github.com/inklabs/goauth2"
)

var funcMap = template.FuncMap{
	"formatDate": formatDate,
	"goAuth2Version": func() string {
		return goauth2.Version
	},
}

func formatDate(timestamp uint64, layout string) string {
	return time.Unix(int64(timestamp), 0).UTC().Format(layout)
}
