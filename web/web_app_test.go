package web_test

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock/provider/seededclock"
	"github.com/inklabs/rangedb/pkg/clock/provider/sequentialclock"
	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/inklabs/rangedb/provider/jsonrecordserializer"
	"github.com/inklabs/rangedb/rangedbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

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
	userID2                = "1c1a688de1c5433a8e41db9192b2ae98"
	username               = "john123"
	username2              = "doe123"
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
	gorillaCSRFTokenKey    = "gorilla.csrf.Token"
)

var (
	issueTime              = time.Date(2020, 05, 1, 8, 0, 0, 0, time.UTC)
	issueTimePlus10Minutes = issueTime.Add(10 * time.Minute)
	issueTimePlus11Minutes = issueTime.Add(11 * time.Minute)
	issueTimePlus1Hour     = issueTime.Add(1 * time.Hour)
)

func Test_Login(t *testing.T) {
	// Given
	app := newApp(t)

	t.Run("serves login form", func(t *testing.T) {
		// Given
		uri := url.URL{
			Path:     "/login",
			RawQuery: getAuthorizeParams().Encode(),
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)

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

	t.Run("fails to serve login form from failing template filesystem", func(t *testing.T) {
		// Given
		app := newApp(t,
			web.WithTemplateFS(failingFilesystem{}),
		)

		uri := url.URL{
			Path:     "/login",
			RawQuery: getAuthorizeParams().Encode(),
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)

		// When
		app.ServeHTTP(w, r)

		// Then
		body := w.Body.String()
		require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Equal(t, "HTTP/1.1", w.Result().Proto)
		assert.Contains(t, body, "internal error")
		// TODO: verify log message
	})
}

func TestListClientApplications(t *testing.T) {
	t.Run("list 2 client applications", func(t *testing.T) {
		// Given
		eventStore := getStoreWithEvents(t,
			goauth2.UserWasOnBoarded{
				UserID:       adminUserID,
				Username:     username,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasGrantedAdministratorRole{
				UserID:         adminUserID,
				GrantingUserID: adminUserID,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     web.ClientIDTODO,
				ClientSecret: web.ClientSecretTODO,
				RedirectURI:  redirectURI,
				UserID:       userID,
			},
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

		goAuth2App, err := goauth2.New(goauth2.WithStore(eventStore))
		require.NoError(t, err)
		app := newApp(t,
			web.WithGoAuth2App(goAuth2App),
		)
		loggedInCookies := loginAdminUser(t, app, username, password)

		uri := url.URL{
			Path: "/admin/list-client-applications",
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
		addCookies(r, loggedInCookies)

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, "HTTP/1.1", w.Result().Proto)
		body := w.Body.String()
		assert.Contains(t, body, clientID)
	})

}

func TestListUsers(t *testing.T) {
	// Given
	eventStore := getStoreWithEvents(t,
		goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     username,
			PasswordHash: passwordHash,
		},
		goauth2.UserWasGrantedAdministratorRole{
			UserID:         userID,
			GrantingUserID: userID,
		},
		goauth2.UserWasOnBoarded{
			UserID:       userID2,
			Username:     username2,
			PasswordHash: passwordHash,
		},
		goauth2.ClientApplicationWasOnBoarded{
			ClientID:     web.ClientIDTODO,
			ClientSecret: web.ClientSecretTODO,
			RedirectURI:  redirectURI,
			UserID:       userID,
		},
	)

	goAuth2App, err := goauth2.New(goauth2.WithStore(eventStore))
	require.NoError(t, err)
	app := newApp(t,
		web.WithGoAuth2App(goAuth2App),
	)

	loggedInCookies := loginAdminUser(t, app, username, password)

	t.Run("list 2 users", func(t *testing.T) {
		// Given
		uri := url.URL{
			Path: "/admin/list-users",
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
		addCookies(r, loggedInCookies)

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusOK, w.Result().StatusCode, w.Body)
		assert.Equal(t, "HTTP/1.1", w.Result().Proto)
		body := w.Body.String()
		assert.Contains(t, body, userID)
		assert.Contains(t, body, userID2)
	})

	t.Run("redirects un-authenticated user to login page", func(t *testing.T) {
		// Given
		uri := url.URL{
			Path: "/admin/list-users",
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
		assert.Equal(t, "HTTP/1.1", w.Result().Proto)

		params := &url.Values{}
		params.Set("redirect", "/admin/list-users")
		expectedLocaiton := url.URL{
			Path:     "/admin-login",
			RawQuery: params.Encode(),
		}
		require.Equal(t, expectedLocaiton.String(), w.Header().Get("Location"))
	})

	t.Run("redirects authenticated, non-admin user to login page", func(t *testing.T) {
		// Given
		loggedInCookies := loginAdminUser(t, app, username2, password)
		uri := url.URL{
			Path: "/admin/list-users",
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
		addCookies(r, loggedInCookies)

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
		assert.Equal(t, "HTTP/1.1", w.Result().Proto)

		params := &url.Values{}
		params.Set("redirect", "/admin/list-users")
		expectedLocaiton := url.URL{
			Path:     "/admin-login",
			RawQuery: params.Encode(),
		}
		require.Equal(t, expectedLocaiton.String(), w.Header().Get("Location"))
	})
}

func addCookies(r *http.Request, cookieLists ...[]*http.Cookie) {
	for _, cookies := range cookieLists {
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
	}
}

func loginAdminUser(t *testing.T, app http.Handler, username, password string) []*http.Cookie {
	// Given
	uri := url.URL{
		Path: "/admin-login",
	}
	params := url.Values{}
	params.Set("username", username)
	params.Set("password", password)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, uri.String(), strings.NewReader(params.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")

	// When
	app.ServeHTTP(w, r)

	// Then
	require.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
	assert.Equal(t, "HTTP/1.1", w.Result().Proto)
	require.Len(t, w.Result().Cookies(), 1)
	require.Equal(t, "/admin/list-users", w.Header().Get("Location"))

	return w.Result().Cookies()
}

func TestAddUser(t *testing.T) {
	// Given
	eventStore := getStoreWithEvents(t,
		goauth2.UserWasOnBoarded{
			UserID:         adminUserID,
			Username:       email,
			PasswordHash:   passwordHash,
			GrantingUserID: adminUserID,
		},
		goauth2.UserWasGrantedAdministratorRole{
			UserID:         adminUserID,
			GrantingUserID: adminUserID,
		},
		goauth2.ClientApplicationWasOnBoarded{
			ClientID:     web.ClientIDTODO,
			ClientSecret: web.ClientSecretTODO,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		},
	)
	goAuth2App, err := goauth2.New(goauth2.WithStore(eventStore))
	require.NoError(t, err)
	uuidGenerator := rangedbtest.NewSeededUUIDGenerator()
	app := newApp(t,
		web.WithGoAuth2App(goAuth2App),
		web.WithUUIDGenerator(uuidGenerator),
	)
	loggedInCookies := loginAdminUser(t, app, email, password)

	t.Run("shows form", func(t *testing.T) {
		// Given
		uri := url.URL{
			Path: "/admin/add-user",
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
		addCookies(r, loggedInCookies)

		// When
		app.ServeHTTP(w, r)

		// Then
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, "HTTP/1.1", w.Result().Proto)
		assert.Contains(t, w.Body.String(), `Add User`)
		require.Len(t, w.Result().Cookies(), 1)
		cookies := w.Result().Cookies()
		csrfToken := csrfTokenFromBody(t, w.Body)

		t.Run("adds a user", func(t *testing.T) {
			// Given
			params := &url.Values{}
			params.Set("username", username)
			params.Set("password", password)
			params.Set("confirm_password", password)
			params.Set(gorillaCSRFTokenKey, csrfToken)

			uri := url.URL{
				Path: "/admin/add-user",
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, uri.String(), strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			addCookies(r, loggedInCookies, cookies)

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			assert.Equal(t, "HTTP/1.1", w.Result().Proto)
			require.Equal(t, "/admin/list-users", w.Header().Get("Location"))
			require.Len(t, w.Result().Cookies(), 1)
			cookies := w.Result().Cookies()

			t.Run("list users contains newly created user and flash message", func(t *testing.T) {
				uri := url.URL{
					Path: "/admin/list-users",
				}
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
				addCookies(r, cookies)

				// When
				app.ServeHTTP(w, r)

				// Then
				require.Equal(t, http.StatusOK, w.Result().StatusCode)
				actualBody := w.Body.String()
				assert.Contains(t, actualBody, uuidGenerator.Get(1))
				assert.Contains(t, actualBody, username)
				assert.Contains(t, actualBody, fmt.Sprintf("User (%s) was added", username))
			})
		})

		t.Run("errors when username or password are missing", func(t *testing.T) {
			// Given
			params := &url.Values{}
			params.Set(gorillaCSRFTokenKey, csrfToken)

			uri := url.URL{
				Path: "/admin/add-user",
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, uri.String(), strings.NewReader(params.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
			addCookies(r, loggedInCookies, cookies)

			// When
			app.ServeHTTP(w, r)

			// Then
			require.Equal(t, http.StatusFound, w.Result().StatusCode)
			assert.Equal(t, "HTTP/1.1", w.Result().Proto)
			require.Equal(t, "/admin/add-user", w.Header().Get("Location"))
			require.Len(t, w.Result().Cookies(), 1)
			cookies := w.Result().Cookies()

			t.Run("flashes missing username or password message", func(t *testing.T) {
				uri := url.URL{
					Path: "/admin/add-user",
				}
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
				addCookies(r, cookies)

				// When
				app.ServeHTTP(w, r)

				// Then
				require.Equal(t, http.StatusOK, w.Result().StatusCode)
				actualBody := w.Body.String()
				assert.Contains(t, actualBody, "username or password are required")
				require.Len(t, w.Result().Cookies(), 2)
				cookies := w.Result().Cookies()

				t.Run("dons not flash after showing once", func(t *testing.T) {
					uri := url.URL{
						Path: "/admin/add-user",
					}
					w := httptest.NewRecorder()
					r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
					for _, cookie := range cookies {
						r.AddCookie(cookie)
					}

					// When
					app.ServeHTTP(w, r)

					// Then
					require.Equal(t, http.StatusOK, w.Result().StatusCode)
					actualBody := w.Body.String()
					assert.NotContains(t, actualBody, "username or password are required")
				})
			})
		})

		t.Run("errors when confirm_password does not match password", func(t *testing.T) {
			// Given

			// When

			// Then
			// TODO: flash failure due to unmatched password
		})

		t.Run("errors from invalid form request", func(t *testing.T) {
			// Given

			// When

			// Then
			// TODO: flash failure due to invalid request
		})

		t.Run("errors from CSRF", func(t *testing.T) {
			// Given

			// When

			// Then
			// TODO: flash failure due to invalid request
		})
	})
}

func TestAdmin_Login(t *testing.T) {
	// Given
	app := newApp(t)

	t.Run("serves login form", func(t *testing.T) {
		// Given
		uri := url.URL{
			Path: "/admin-login",
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, uri.String(), nil)

		// When
		app.ServeHTTP(w, r)

		// Then
		body := w.Body.String()
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, "HTTP/1.1", w.Result().Proto)
		assert.Contains(t, body, "form")
	})
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
		goAuth2App, err := goauth2.New(
			goauth2.WithStore(eventStore),
			goauth2.WithClock(seededclock.New(issueTime)),
		)
		require.NoError(t, err)
		app := newApp(t,
			web.WithGoAuth2App(goAuth2App),
		)

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
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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

			goAuth2App, err := goauth2.New(
				goauth2.WithStore(eventStore),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
				goauth2.WithClock(seededclock.New(issueTime)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
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

			goAuth2App, err := goauth2.New(
				goauth2.WithStore(eventStore),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
				goauth2.WithClock(seededclock.New(issueTime)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
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
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
		app := newApp(t)
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
		app := newApp(t)
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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			app := newApp(t)
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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(accessToken)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(accessToken)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
				goauth2.WithClock(sequentialclock.New()),
				goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(accessToken)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
			app := newApp(t)
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
			goAuth2App, err := goauth2.New(
				goauth2.WithStore(getStoreWithClientApplicationAndUserOnBoarded(t)),
			)
			require.NoError(t, err)
			app := newApp(t,
				web.WithGoAuth2App(goAuth2App),
			)

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
		app := newApp(t)
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
		app := newApp(t)
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

	goAuth2App, err := goauth2.New(options...)
	require.NoError(t, err)

	app := newApp(t,
		web.WithGoAuth2App(goAuth2App),
	)

	return app
}

func newApp(t *testing.T, options ...web.Option) http.Handler {
	csrfAuthenticationKey := securecookie.GenerateRandomKey(32)
	authenticationKey := securecookie.GenerateRandomKey(64)
	encryptionKey := securecookie.GenerateRandomKey(32)

	options = append([]web.Option{
		web.WithCSRFAuthKey(csrfAuthenticationKey),
		web.WithSessionKeyPair(web.SessionKeyPair{
			AuthenticationKey: authenticationKey,
			EncryptionKey:     encryptionKey,
		}),
	}, options...)

	app, err := web.New(options...)
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

func csrfTokenFromBody(t *testing.T, body io.Reader) string {
	doc, err := html.Parse(body)
	require.NoError(t, err)

	var csrfToken string

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == gorillaCSRFTokenKey {
					for _, attr := range n.Attr {
						if attr.Key == "value" {
							csrfToken = attr.Val
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return csrfToken
}
