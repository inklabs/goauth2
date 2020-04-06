package web_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2/web"
	"github.com/inklabs/goauth2/web/pkg/templateloader/provider/livefilesystemloader"
	"github.com/inklabs/goauth2/web/webtest"
)

const (
	clientId         = "9a88a97ad2834c0b987d734482499ee5"
	redirectUri      = "https://www.example.com"
	codeResponseType = "code"
	state            = "some-state"
	scope            = "read_write"
	emailAddress     = "john@example.com"
	password         = "pass123"
)

func Test_Login_ServesLoginForm(t *testing.T) {
	// Given
	app := web.New(
		web.WithTemplateLoader(livefilesystemloader.New("./templates")),
	)
	params := getAuthorizeParams()
	uri := fmt.Sprintf("/login?%s", params.Encode())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, uri, nil)

	// When
	app.ServeHTTP(w, r)

	// Then
	body := w.Body.String()
	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.Equal(t, "HTTP/1.1", w.Result().Proto)
	assert.Contains(t, body, "form")
	assert.Contains(t, body, clientId)
	assert.Contains(t, body, redirectUri)
	assert.Contains(t, body, codeResponseType)
	assert.Contains(t, body, scope)
	assert.Contains(t, body, state)
}

func Test_Login_FailsToServeLoginForm(t *testing.T) {
	// Given
	app := web.New(
		web.WithTemplateLoader(webtest.NewFailingTemplateLoader()),
	)
	params := getAuthorizeParams()
	uri := fmt.Sprintf("/login?%s", params.Encode())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, uri, nil)

	// When
	app.ServeHTTP(w, r)

	// Then
	body := w.Body.String()
	require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
	assert.Equal(t, "HTTP/1.1", w.Result().Proto)
	assert.Contains(t, body, "internal error")
}

func getAuthorizeParams() *url.Values {
	params := &url.Values{}
	params.Set("email", emailAddress)
	params.Set("password", password)
	params.Set("client_id", clientId)
	params.Set("redirect_uri", redirectUri)
	params.Set("response_type", codeResponseType)
	params.Set("scope", scope)
	params.Set("state", state)
	return params
}
