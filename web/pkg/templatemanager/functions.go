package templatemanager

import (
	"html/template"
	"time"
)

var FuncMap = template.FuncMap{
	"formatDate": formatDate,
}

func formatDate(timestamp uint64, layout string) string {
	return time.Unix(int64(timestamp), 0).UTC().Format(layout)
}
