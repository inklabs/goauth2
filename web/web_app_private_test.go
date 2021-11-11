package web

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_writeJsonResponse_FailsFromInvalidJson(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	invalidJSON := map[string]float64{
		"foo": math.Inf(1),
	}

	// When
	writeJSONResponse(w, invalidJSON)

	// Then
	body := w.Body.String()
	require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
	assert.Equal(t, "HTTP/1.1", w.Result().Proto)
	assert.Contains(t, body, "internal error")
}
