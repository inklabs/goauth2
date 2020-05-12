package templatemanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFuncMap_formatDate(t *testing.T) {
	// When
	actual := formatDate(1589260539, "Jan 02, 2006 15:04:05 UTC")

	// Then
	assert.Equal(t, "May 12, 2020 05:15:39 UTC", actual)
}
