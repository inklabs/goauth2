package web_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock/provider/seededclock"
	"github.com/inklabs/rangedb/pkg/clock/provider/sequentialclock"
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
	clientID2              = "da975f24538942a1872915d0982a9b50"
	clientSecret2          = "977c8a5726e148c0aa1b48ebd435a02c"
	userID                 = "25c807edd664438985401b2282678b13"
	adminUserID            = "873aeb9386724213b4c1410bce9f838c"
	email                  = "john@example.com"
	password               = "Pass123!"
	passwordHash           = "$2a$10$U6ej0p2d9Y8OO2635R7l/O4oEBvxgc9o6gCaQ1wjMZ77dr4qGl8nu"
	redirectURI            = "https://example.com/oauth2/callback"
	codeResponseType       = "code"
	state                  = "some-state"
	scope                  = "read_write"
	accessToken            = "f5bb89d486ee458085e476871b177ff4"
	nextAccessToken        = "61272356284f4340b2b1f3f1400ad4d9"
	refreshToken           = "df00e449f5f4489ea2d26e18f0015274"
	nextRefreshToken       = "915ce1b4bb8748e6930595de08cbe328"
	authorizationCode      = "2441fd0e215f4568b67c872d39f95a3f"
	clientCredentialsGrant = "client_credentials"
	ROPCGrant              = "password"
	RefreshTokenGrant      = "refresh_token"
	ImplicitGrant          = "token"
	AuthorizationCodeGrant = "authorization_code"
)

var (
	issueTime              = time.Date(2020, 05, 1, 8, 0, 0, 0, time.UTC)
	issueTimePlus10Minutes = issueTime.Add(10 * time.Minute)
	issueTimePlus11Minutes = issueTime.Add(11 * time.Minute)
	issueTimePlus1Hour     = issueTime.Add(1 * time.Hour)
)

func Test_Login(t *testing.T) {
	t.Run("serves login form", func(t *testing.T) {
		// Given
		app, err := web.New()
		require.NoError(t, err)
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
		assert.Contains(t, body, redirectURI)
		assert.Contains(t, body, codeResponseType)
		assert.Contains(t, body, scope)
		assert.Contains(t, body, state)
	})

	t.Run("fails to serve login form", func(t *testing.T) {
		// Given
		app, err := web.New(
			web.WithTemplateFilesystem(failingFilesystem{}),
		)
		require.NoError(t, err)
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
	})
}

func TestListClientApplications(t *testing.T) {
	// Given
	eventStore := getStoreWithEvents(t,
		goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		},
		goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID2,
			ClientSecret: clientSecret2,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		},
	)

	goauth2App, err := goauth2.New(goauth2.WithStore(eventStore))
	require.NoError(t, err)
	app, err := web.New(
		web.WithGoauth2App(goauth2App),
	)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/client-applications", nil)

	// When
	app.ServeHTTP(w, r)

	// Then
	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.Equal(t, "HTTP/1.1", w.Result().Proto)
	body := w.Body.String()
	assert.Contains(t, body, clientID)
}

func Test_TokenEndpoint(t *testing.T) {
	const tokenURI = "/token"
	t.Run("Client Credentials Grant Type with client application on-boarded", func(t *testing.T) {
		// Given
		eventStore := getStoreWithEvents(t,
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
		)
		goauth2App, err := goauth2.New(
			goauth2.WithStore(eventStore),
			goauth2.WithClock(seededclock.New(issueTime)),
		)
		require.NoError(t, err)
		app, err := web.New(
			web.WithGoauth2App(goauth2App),
		)
		require.NoError(t, err)
		params := &url.Values{}
		params.Set("grant_type", clientCredentialsGrant)
		params.Set("scope", scope)

		t.Run("issues access token", func(t *testing.T) {
			// Given
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			expiresAt := issueTimePlus1Hour.Unix()
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
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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
		params := &url.Values{}
		params.Set("grant_type", ROPCGrant)
		params.Set("username", email)
		params.Set("password", password)
		params.Set("scope", scope)

		t.Run("issues access and refresh token", func(t *testing.T) {
			// Given
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
				goauth2.WithClock(seededclock.New(issueTime)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goAuth2App))
			require.NoError(t, err)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			expiresAt := issueTimePlus1Hour.Unix()
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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goAuth2App))
			require.NoError(t, err)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goAuth2App))
			require.NoError(t, err)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goAuth2App))
			require.NoError(t, err)
			params := &url.Values{}
			params.Set("grant_type", ROPCGrant)
			params.Set("username", "wrong-email@example.com")
			params.Set("password", password)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goAuth2App))
			require.NoError(t, err)
			params := &url.Values{}
			params.Set("grant_type", ROPCGrant)
			params.Set("username", email)
			params.Set("password", "wrong-password")
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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

	t.Run("Authorization Code Grant Type", func(t *testing.T) {
		t.Run("issues access and refresh token", func(t *testing.T) {
			// Given
			app := getAppWithAuthorizationCodeIssued(t)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", authorizationCode)
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			expiresAt := issueTimePlus1Hour.Unix()
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
			app := getAppWithAuthorizationCodeIssued(t)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", authorizationCode)
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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
			app := getAppWithAuthorizationCodeIssued(t)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", authorizationCode)
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, "invalid-client-secret")
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_client"}`, w.Body.String())
		})

		t.Run("fails with invalid redirect URI", func(t *testing.T) {
			// Given
			app := getAppWithAuthorizationCodeIssued(t)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", authorizationCode)
			params.Set("redirect_uri", "https://wrong.example.com")
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())
		})

		t.Run("fails with invalid authorization code", func(t *testing.T) {
			// Given
			app := getAppWithAuthorizationCodeIssued(t)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", "invalid-code")
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())
		})

		t.Run("fails with expired authorization code", func(t *testing.T) {
			// Given
			app := getAppWithAuthorizationCodeIssued(t,
				goauth2.WithClock(seededclock.New(issueTimePlus11Minutes)),
			)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", authorizationCode)
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())
		})

		t.Run("fails with authorization code for wrong client application id", func(t *testing.T) {
			// Given
			eventStore := getStoreWithEvents(t,
				goauth2.ClientApplicationWasOnBoarded{
					ClientID:     clientID,
					ClientSecret: clientSecret,
					RedirectURI:  redirectURI,
					UserID:       adminUserID,
				},
				goauth2.ClientApplicationWasOnBoarded{
					ClientID:     clientID2,
					ClientSecret: clientSecret2,
					RedirectURI:  redirectURI,
					UserID:       adminUserID,
				},
				goauth2.AuthorizationCodeWasIssuedToUser{
					AuthorizationCode: authorizationCode,
					UserID:            userID,
					ClientID:          clientID2,
					ExpiresAt:         issueTimePlus10Minutes.Unix(),
					Scope:             scope,
				},
			)

			goauth2App, err := goauth2.New(
				goauth2.WithStore(eventStore),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
				goauth2.WithClock(seededclock.New(issueTime)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", authorizationCode)
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())
		})

		t.Run("fails with previously used authorization code", func(t *testing.T) {
			// Given
			eventStore := getStoreWithEvents(t,
				goauth2.ClientApplicationWasOnBoarded{
					ClientID:     clientID,
					ClientSecret: clientSecret,
					RedirectURI:  redirectURI,
					UserID:       adminUserID,
				},
				goauth2.AuthorizationCodeWasIssuedToUser{
					AuthorizationCode: authorizationCode,
					UserID:            userID,
					ClientID:          clientID,
					ExpiresAt:         issueTimePlus10Minutes.Unix(),
					Scope:             scope,
				},
				goauth2.AccessTokenWasIssuedToUserViaAuthorizationCodeGrant{
					AuthorizationCode: authorizationCode,
					UserID:            userID,
					ClientID:          clientID,
					Scope:             scope,
					ExpiresAt:         issueTimePlus1Hour.Unix(),
				},
			)

			goauth2App, err := goauth2.New(
				goauth2.WithStore(eventStore),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
				goauth2.WithClock(seededclock.New(issueTime)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := &url.Values{}
			params.Set("grant_type", AuthorizationCodeGrant)
			params.Set("code", authorizationCode)
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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

	t.Run("Refresh Token Grant Type", func(t *testing.T) {
		t.Run("issues access and refresh token to user from refresh token request", func(t *testing.T) {
			// Given
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken, nextRefreshToken)),
				goauth2.WithClock(seededclock.New(issueTime)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goAuth2App))
			require.NoError(t, err)
			params := &url.Values{}
			params.Set("grant_type", ROPCGrant)
			params.Set("username", email)
			params.Set("password", password)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			app.ServeHTTP(w, r)
			require.Equal(t, http.StatusOK, w.Result().StatusCode)

			var accessTokenResponse web.AccessTokenResponse
			err = json.Unmarshal(w.Body.Bytes(), &accessTokenResponse)
			require.NoError(t, err)

			refreshParams := &url.Values{}
			refreshParams.Set("grant_type", RefreshTokenGrant)
			refreshParams.Set("refresh_token", accessTokenResponse.RefreshToken)
			refreshParams.Set("scope", accessTokenResponse.Scope)
			w = httptest.NewRecorder()
			r = httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(refreshParams.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			expiresAt := issueTimePlus1Hour.Unix()
			expectedBody := fmt.Sprintf(`{
				"access_token": "%s",
				"expires_at": %d,
				"token_type": "Bearer",
				"scope": "%s",
				"refresh_token": "%s"
			}`, nextAccessToken, expiresAt, scope, nextRefreshToken)

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusOK, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.JSONEq(t, expectedBody, w.Body.String())
		})

		t.Run("refresh token grant fails from invalid refresh token", func(t *testing.T) {
			// Given
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goAuth2App))
			require.NoError(t, err)
			params := &url.Values{}
			params.Set("grant_type", ROPCGrant)
			params.Set("username", email)
			params.Set("password", password)
			params.Set("scope", scope)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			app.ServeHTTP(w, r)
			require.Equal(t, http.StatusOK, w.Result().StatusCode)

			var accessTokenResponse web.AccessTokenResponse
			err = json.Unmarshal(w.Body.Bytes(), &accessTokenResponse)
			require.NoError(t, err)

			refreshParams := &url.Values{}
			refreshParams.Set("grant_type", RefreshTokenGrant)
			refreshParams.Set("refresh_token", "wrong-token")
			w = httptest.NewRecorder()
			r = httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(refreshParams.Encode()))
			r.SetBasicAuth(clientID, clientSecret)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
			assertJsonHeaders(t, w)
			assert.JSONEq(t, `{"error":"invalid_grant"}`, w.Body.String())
		})
	})

	t.Run("fails with invalid HTTP form request", func(t *testing.T) {
		// Given
		app, err := web.New()
		require.NoError(t, err)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader("%invalid-form"))
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
		app, err := web.New()
		require.NoError(t, err)
		params := &url.Values{}
		params.Set("grant_type", "invalid-grant-type")
		params.Set("scope", scope)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, tokenURI, strings.NewReader(params.Encode()))
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

func Test_AuthorizeEndpoint(t *testing.T) {
	const authorizeURI = "/authorize"
	t.Run("authorization code grant", func(t *testing.T) {
		t.Run("grants authorization code and redirects", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			assert.Equal(t, "", w.Body.String())
			expectedLocation := "https://example.com/oauth2/callback?code=2441fd0e215f4568b67c872d39f95a3f&state=some-state"
			assert.Equal(t, expectedLocation, w.Header().Get("Location"))
		})

		t.Run("fails with missing user", func(t *testing.T) {
			// Given
			app, err := web.New()
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("username", "wrong-email@example.com")
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			assert.Equal(t, "", w.Body.String())
			expectedLocation := "https://example.com/oauth2/callback?error=access_denied&state=some-state"
			assert.Equal(t, expectedLocation, w.Header().Get("Location"))
		})

		t.Run("fails with invalid client id", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("client_id", "invalid-client-id")

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
			assert.Contains(t, w.Body.String(), "invalid request")
		})

		t.Run("fails with invalid redirect uri", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("redirect_uri", "https://wrong.example.com")

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
			assert.Contains(t, w.Body.String(), "invalid request")
		})

		t.Run("fails with missing user", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("username", "wrong@example.com")

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			expectedLocation := "https://example.com/oauth2/callback?error=access_denied&state=some-state"
			assert.Equal(t, expectedLocation, w.Header().Get("Location"))
		})

		t.Run("fails with invalid user password", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("password", "wrong-pass")
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			expectedLocation := "https://example.com/oauth2/callback?error=access_denied&state=some-state"
			assert.Equal(t, expectedLocation, w.Header().Get("Location"))
		})
	})

	t.Run("implicit grant", func(t *testing.T) {
		t.Run("grants access token via implicit grant and redirects with URI fragment", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(accessToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("response_type", ImplicitGrant)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			assert.Equal(t, "", w.Body.String())
			expectedLocation := "https://example.com/oauth2/callback#access_token=f5bb89d486ee458085e476871b177ff4&expires_at=1574371565&scope=read_write&state=some-state&token_type=Bearer"
			assert.Equal(t, expectedLocation, w.Header().Get("Location"))
		})

		t.Run("fails with invalid client id", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(accessToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("response_type", ImplicitGrant)
			params.Set("client_id", "invalid-client-id")

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
			assert.Contains(t, w.Body.String(), "invalid request")
		})

		t.Run("fails with invalid redirect uri", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(accessToken)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("response_type", ImplicitGrant)
			params.Set("redirect_uri", "https://wrong.example.com")

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
			assert.Contains(t, w.Body.String(), "invalid request")
		})

		t.Run("fails with missing user", func(t *testing.T) {
			// Given
			app, err := web.New()
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("response_type", ImplicitGrant)
			params.Set("username", "wrong-email@example.com")
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			expectedLocation := "https://example.com/oauth2/callback?error=access_denied&state=some-state"
			assert.Equal(t, expectedLocation, w.Header().Get("Location"))
		})

		t.Run("fails with invalid user password", func(t *testing.T) {
			// Given
			goauth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
			)
			require.NoError(t, err)
			app, err := web.New(web.WithGoauth2App(goauth2App))
			require.NoError(t, err)
			params := getAuthorizeParams()
			params.Set("response_type", ImplicitGrant)
			params.Set("password", "wrong-pass")
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			expectedLocation := "https://example.com/oauth2/callback?error=access_denied&state=some-state"
			assert.Equal(t, expectedLocation, w.Header().Get("Location"))
		})
	})

	t.Run("fails with invalid HTTP form request", func(t *testing.T) {
		// Given
		app, err := web.New()
		require.NoError(t, err)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader("%invalid-form"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "invalid request")
	})

	t.Run("fails with unsupported response type", func(t *testing.T) {
		// Given
		app, err := web.New()
		require.NoError(t, err)
		params := getAuthorizeParams()
		params.Set("response_type", "invalid-response-type")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, authorizeURI, strings.NewReader(params.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusFound, w.Result().StatusCode)
		assert.Equal(t, "", w.Body.String())
		expectedLocation := "https://example.com/oauth2/callback?error=unsupported_response_type&state=some-state"
		assert.Equal(t, expectedLocation, w.Header().Get("Location"))
	})
}

func Test_SavedEvents(t *testing.T) {
	// Given
	thingWasDone := &rangedbtest.ThingWasDone{
		ID:     "abc",
		Number: 123,
	}
	thatWasDone := &rangedbtest.ThatWasDone{
		ID: "xyz",
	}
	events := web.SavedEvents{
		thingWasDone,
		thatWasDone,
	}

	t.Run("contains", func(t *testing.T) {
		// Then
		assert.True(t, events.Contains(&rangedbtest.ThingWasDone{}))
		assert.True(t, events.Contains(&rangedbtest.ThingWasDone{}, &rangedbtest.ThatWasDone{}))
		assert.False(t, events.Contains(&rangedbtest.AnotherWasComplete{}))
		assert.False(t, events.Contains(&rangedbtest.AnotherWasComplete{}, &rangedbtest.ThingWasDone{}))
	})

	t.Run("contains any", func(t *testing.T) {
		// Then
		assert.True(t, events.ContainsAny(&rangedbtest.AnotherWasComplete{}, &rangedbtest.ThingWasDone{}))
		assert.True(t, events.ContainsAny(&rangedbtest.ThingWasDone{}, &rangedbtest.ThatWasDone{}))
	})

	t.Run("get finds an event from a list of pointer events", func(t *testing.T) {
		// Given
		var event rangedbtest.ThingWasDone

		// When
		isFound := events.Get(&event)

		// Then
		require.True(t, isFound)
		assert.Equal(t, *thingWasDone, event)
	})

	t.Run("get finds an event from a list of value events", func(t *testing.T) {
		// Given
		thingWasDone := rangedbtest.ThingWasDone{
			ID:     "abc",
			Number: 123,
		}
		thatWasDone := rangedbtest.ThatWasDone{
			ID: "xyz",
		}
		events := web.SavedEvents{
			thingWasDone,
			thatWasDone,
		}
		var event rangedbtest.ThingWasDone

		// When
		isFound := events.Get(&event)

		// Then
		require.True(t, isFound)
		assert.Equal(t, thingWasDone, event)
	})

	t.Run("get does not find an event", func(t *testing.T) {
		// Given
		var event rangedbtest.AnotherWasComplete

		// When
		isFound := events.Get(&event)

		// Then
		require.False(t, isFound)
		assert.Equal(t, rangedbtest.AnotherWasComplete{}, event)
	})
}

func getAppWithAuthorizationCodeIssued(t *testing.T, options ...goauth2.Option) http.Handler {
	eventStore := getStoreWithEvents(t,
		goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		},
		goauth2.AuthorizationCodeWasIssuedToUser{
			AuthorizationCode: authorizationCode,
			UserID:            userID,
			ClientID:          clientID,
			ExpiresAt:         issueTimePlus10Minutes.Unix(),
			Scope:             scope,
		},
	)

	options = append([]goauth2.Option{
		goauth2.WithStore(eventStore),
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
		goauth2.WithClock(seededclock.New(issueTime)),
	}, options...)

	goauth2App, err := goauth2.New(options...)
	require.NoError(t, err)

	app, err := web.New(web.WithGoauth2App(goauth2App))
	require.NoError(t, err)

	return app
}

func getAuthorizeParams() *url.Values {
	params := &url.Values{}
	params.Set("username", email)
	params.Set("password", password)
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
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
	ctx := rangedbtest.TimeoutContext(t)
	for _, event := range events {
		_, err := eventStore.Save(ctx, &rangedb.EventRecord{Event: event})
		require.NoError(t, err)
	}

	return eventStore
}

func getStoreWithClientApplicationAndUserOnBoarded(t *testing.T) rangedb.Store {
	return getStoreWithEvents(t,
		goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		},
		goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     email,
			PasswordHash: passwordHash,
		},
	)
}

type failingFilesystem struct{}

func (f failingFilesystem) Open(_ string) (fs.File, error) {
	return nil, fmt.Errorf("failingFilesystem:Open")
}
