package web_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/inklabs/rangedb/provider/jsonrecordserializer"
	"github.com/inklabs/rangedb/rangedbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/goauth2test"
	"github.com/inklabs/goauth2/web"
)

const (
	clientID               = "fe3c986043cd4a0ebe5e181ba2baa500"
	clientSecret           = "f29a2881e697403395e53ca173caa217"
	userID                 = "25c807edd664438985401b2282678b13"
	adminUserID            = "873aeb9386724213b4c1410bce9f838c"
	email                  = "john@example.com"
	password               = "Pass123!"
	passwordHash           = "$2a$10$U6ej0p2d9Y8OO2635R7l/O4oEBvxgc9o6gCaQ1wjMZ77dr4qGl8nu"
	redirectUri            = "https://www.example.com"
	codeResponseType       = "code"
	state                  = "some-state"
	scope                  = "read_write"
	accessToken            = "f5bb89d486ee458085e476871b177ff4"
	refreshToken           = "df00e449f5f4489ea2d26e18f0015274"
	clientCredentialsGrant = "client_credentials"
	ROPCGrant              = "password"
)

var TemplateAssets = http.Dir("./templates")

func Test_Login_ServesLoginForm(t *testing.T) {
	// Given
	app := web.New(
		web.WithTemplateFilesystem(TemplateAssets),
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
	assert.Contains(t, body, clientID)
	assert.Contains(t, body, redirectUri)
	assert.Contains(t, body, codeResponseType)
	assert.Contains(t, body, scope)
	assert.Contains(t, body, state)
}

func Test_Login_FailsToServeLoginForm(t *testing.T) {
	// Given
	app := web.New(
		web.WithTemplateFilesystem(failingFilesystem{}),
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

func Test_TokenEndpoint(t *testing.T) {
	const tokenUri = "/token"
	t.Run("Client Credentials Grant Type with client application on-boarded", func(t *testing.T) {
		// Given
		eventStore := getStoreWithEvents(t,
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectUri:  redirectUri,
				UserID:       adminUserID,
			},
		)
		app := web.New(
			web.WithGoauth2App(goauth2.New(goauth2.WithStore(eventStore))),
		)
		params := &url.Values{}
		params.Set("grant_type", clientCredentialsGrant)
		params.Set("scope", scope)

		t.Run("issues access and refresh token", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			expiresAt := 1574371565
			expectedBody := fmt.Sprintf(`{
				"access_token": "%s",
				"expires_at": %d,
				"token_type": "Bearer",
				"scope": "%s"
			}`, accessToken, expiresAt, scope)

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusOK, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.JSONEq(t, expectedBody, w.Body.String())
		})

		t.Run("fails with missing clientID and clientSecret", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_client"}`, w.Body.String())
		})

		t.Run("fails with invalid client application id", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth("invalid-client-id", clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_client"}`, w.Body.String())
		})

		t.Run("fails with invalid client application secret", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, "invalid-client-secret")
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_client"}`, w.Body.String())
		})
	})

	t.Run("ROPC Grant Type with client application and user on-boarded", func(t *testing.T) {
		// Given
		eventStore := getStoreWithEvents(t,
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectUri:  redirectUri,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		)
		tokenGenerator := goauth2test.NewSeededTokenGenerator(refreshToken)
		goAuth2App := goauth2.New(
			goauth2.WithStore(eventStore),
			goauth2.WithTokenGenerator(tokenGenerator),
		)
		app := web.New(web.WithGoauth2App(goAuth2App))
		params := &url.Values{}
		params.Set("grant_type", ROPCGrant)
		params.Set("username", email)
		params.Set("password", password)
		params.Set("scope", scope)

		t.Run("issues access and refresh token", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			expiresAt := 1574371565
			expectedBody := fmt.Sprintf(`{
				"access_token": "%s",
				"expires_at": %d,
				"token_type": "Bearer",
				"scope": "%s",
				"refresh_token": "%s"
			}`, accessToken, expiresAt, scope, refreshToken)

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusOK, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.JSONEq(t, expectedBody, w.Body.String())
		})

		t.Run("fails with invalid client application id", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth("invalid-client-id", clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_client"}`, w.Body.String())
		})

		t.Run("fails with invalid client application secret", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, "invalid-client-secret")
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_client"}`, w.Body.String())
		})

		t.Run("fails with missing user", func(t *testing.T) {
			// Given
			params := &url.Values{}
			params.Set("grant_type", ROPCGrant)
			params.Set("username", "wrong-email@example.com")
			params.Set("password", password)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())
		})

		t.Run("fails with invalid user password", func(t *testing.T) {
			// Given
			params := &url.Values{}
			params.Set("grant_type", ROPCGrant)
			params.Set("username", email)
			params.Set("password", "wrong-password")
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())
		})
	})

	t.Run("fails with invalid HTTP form request", func(t *testing.T) {
		// Given
		app := web.New()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader("%invalid-form"))
		r.SetBasicAuth(clientID, clientSecret)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "invalid request")
	})

	t.Run("fails with unsupported grant type", func(t *testing.T) {
		// Given
		app := web.New()
		params := &url.Values{}
		params.Set("grant_type", "invalid-grant-type")
		params.Set("scope", scope)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, tokenUri, strings.NewReader(params.Encode()))
		r.SetBasicAuth(clientID, clientSecret)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assertJsonHeaders(t, w)
		assert.Equal(t, `{"error":"unsupported_grant_type"}`, w.Body.String())
	})
}

func Test_SavedEvents(t *testing.T) {
	// Given
	events := web.SavedEvents{
		&rangedbtest.ThingWasDone{},
		&rangedbtest.ThatWasDone{},
	}

	// Then
	assert.True(t, events.Contains(&rangedbtest.ThingWasDone{}))
	assert.True(t, events.Contains(&rangedbtest.ThingWasDone{}, &rangedbtest.ThatWasDone{}))
	assert.False(t, events.Contains(&rangedbtest.AnotherWasComplete{}))
	assert.False(t, events.Contains(&rangedbtest.AnotherWasComplete{}, &rangedbtest.ThingWasDone{}))
}

func getAuthorizeParams() *url.Values {
	params := &url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectUri)
	params.Set("response_type", codeResponseType)
	params.Set("scope", scope)
	params.Set("state", state)
	return params
}

func assertJsonHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	assert.Equal(t, "application/json;charset=UTF-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

func getStoreWithEvents(t *testing.T, events ...rangedb.Event) rangedb.Store {
	serializer := jsonrecordserializer.New()
	goauth2.BindEvents(serializer)
	eventStore := inmemorystore.New(inmemorystore.WithSerializer(serializer))
	for _, event := range events {
		err := eventStore.Save(event, nil)
		if err != nil {
			t.Errorf("unable to save event: %v", err)
		}
	}

	return eventStore
}

type failingFilesystem struct{}

func (f failingFilesystem) Open(_ string) (http.File, error) {
	return nil, fmt.Errorf("failingFilesystem:Open")
}
