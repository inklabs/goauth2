package web

import (
	"embed"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/inklabs/rangedb/pkg/shortuuid"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/projection"
)

const (
	accessTokenTODO  = "f5bb89d486ee458085e476871b177ff4"
	ClientIDTODO     = "8895e1e5f06644ebb41c26ea5740b246"
	ClientSecretTODO = "c1e847aef925467290b4302e64f3de4e"
	expiresAtTODO    = 1574371565
)

//go:embed static
var staticAssets embed.FS

//go:embed templates
var templates embed.FS

const defaultHost = "0.0.0.0:8080"

// SessionKeyPair holds the keys for a secure cookie session.
type SessionKeyPair struct {
	AuthenticationKey []byte
	EncryptionKey     []byte
}

type webApp struct {
	router          http.Handler
	templateFS      fs.FS
	goAuth2App      *goauth2.App
	uuidGenerator   shortuuid.Generator
	sessionStore    sessions.Store
	sessionKeyPairs []SessionKeyPair
	csrfAuthKey     []byte
	host            string
	projections     struct {
		emailToUserID      *projection.EmailToUserID
		clientApplications *projection.ClientApplications
		users              *projection.Users
	}
}

// Option defines functional option parameters for webApp.
type Option func(*webApp)

// WithTemplateFS is a functional option to inject a fs.FS
func WithTemplateFS(f fs.FS) Option {
	return func(webApp *webApp) {
		webApp.templateFS = f
	}
}

// WithGoAuth2App is a functional option to inject a goauth2.App.
func WithGoAuth2App(goAuth2App *goauth2.App) Option {
	return func(app *webApp) {
		app.goAuth2App = goAuth2App
	}
}

// WithHost is a functional option to inject a tcp4 host.
func WithHost(host string) Option {
	return func(app *webApp) {
		app.host = host
	}
}

// WithUUIDGenerator is a functional option to inject a shortuuid.Generator.
func WithUUIDGenerator(generator shortuuid.Generator) Option {
	return func(app *webApp) {
		app.uuidGenerator = generator
	}
}

// WithCSRFAuthKey is a functional option to inject a CSRF authentication key
func WithCSRFAuthKey(csrfAuthKey []byte) Option {
	return func(app *webApp) {
		app.csrfAuthKey = csrfAuthKey
	}
}

// WithSessionKeyPair is a functional option to inject a session key pair.
//  Useful for rotating session authentication and encryption keys. Old sessions can still
//  be read because the first pair will fail, and the second will be tested.
func WithSessionKeyPair(sessionKeyPairs ...SessionKeyPair) Option {
	return func(app *webApp) {
		app.sessionKeyPairs = sessionKeyPairs
	}
}

// New constructs an webApp.
func New(options ...Option) (*webApp, error) {
	goAuth2App, err := goauth2.New()
	if err != nil {
		return nil, err
	}

	app := &webApp{
		templateFS:    templates,
		goAuth2App:    goAuth2App,
		uuidGenerator: shortuuid.NewUUIDGenerator(),
		host:          defaultHost,
	}

	for _, option := range options {
		option(app)
	}

	err = app.validateCSRFAuthKey()
	if err != nil {
		return nil, err
	}

	err = app.initSessionStore()
	if err != nil {
		return nil, err
	}

	app.initRoutes()
	err = app.initProjections()
	if err != nil {
		return nil, err
	}

	return app, nil
}

func (a *webApp) validateCSRFAuthKey() error {
	if a.csrfAuthKey == nil {
		return fmt.Errorf("missing CSRF authentication key")
	}

	if len(a.csrfAuthKey) != 32 {
		return fmt.Errorf("invalid CSRF authentication key length")
	}

	return nil
}

func (a *webApp) initSessionStore() error {
	var keyPairs [][]byte

	for _, sessionKeyPair := range a.sessionKeyPairs {
		if len(sessionKeyPair.AuthenticationKey) != 64 {
			return fmt.Errorf("invalid session authentication key length")
		}

		if len(sessionKeyPair.EncryptionKey) != 32 {
			return fmt.Errorf("invalid session encryption key length")
		}

		keyPairs = append(keyPairs,
			sessionKeyPair.AuthenticationKey,
			sessionKeyPair.EncryptionKey,
		)
	}

	gob.Register(AuthenticatedUser{})
	a.sessionStore = sessions.NewCookieStore(keyPairs...)
	return nil
}

func (a *webApp) initRoutes() {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/authorize", a.authorize)
	r.HandleFunc("/login", a.login)
	r.HandleFunc("/token", a.token)
	r.PathPrefix("/static/").Handler(cache30Days(http.FileServer(http.FS(staticAssets))))

	a.addAdminRoutes(r)

	a.router = r
}

func (a *webApp) initProjections() error {
	a.projections.emailToUserID = projection.NewEmailToUserID()
	a.projections.clientApplications = projection.NewClientApplications()
	a.projections.users = projection.NewUsers()

	return a.goAuth2App.SubscribeAndReplay(
		a.projections.emailToUserID,
		a.projections.clientApplications,
		a.projections.users,
	)
}

func (a *webApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *webApp) login(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	clientID := params.Get("client_id")
	redirectURI := params.Get("redirect_uri")
	responseType := params.Get("response_type")
	state := params.Get("state")
	scope := params.Get("scope")

	a.renderTemplate(w, "login.gohtml", struct {
		flashMessageVars
		ClientID     string
		RedirectURI  string
		ResponseType string
		Scope        string
		State        string
	}{
		ClientID:         clientID,
		RedirectURI:      redirectURI,
		ResponseType:     responseType,
		Scope:            scope,
		State:            state,
		flashMessageVars: a.getFlashMessageVars(w, r),
	})
}

func (a *webApp) authorize(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeInvalidRequestResponse(w)
		return
	}

	redirectURI := r.Form.Get("redirect_uri")
	responseType := r.Form.Get("response_type")
	state := r.Form.Get("state")

	switch responseType {
	case "code":
		a.handleAuthorizationCodeGrant(w, r)

	case "token":
		a.handleImplicitGrant(w, r)

	default:
		errorRedirect(w, r, redirectURI, "unsupported_response_type", state)

	}
}

func (a *webApp) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	state := r.Form.Get("state")
	scope := r.Form.Get("scope")

	userID, err := a.projections.emailToUserID.GetUserID(username)
	if err != nil {
		errorRedirect(w, r, redirectURI, "access_denied", state)
		return
	}

	// TODO: Change signature for Dispatch from []rangedb.Event to SavedEvents
	events := SavedEvents(a.goAuth2App.Dispatch(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrant{
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Username:    username,
		Password:    password,
		Scope:       scope,
	}))
	var issuedEvent goauth2.AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant
	if !events.Get(&issuedEvent) {
		if events.ContainsAny(
			&goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{},
			&goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI{},
		) {
			writeInvalidRequestResponse(w)
			return
		}

		errorRedirect(w, r, redirectURI, "access_denied", state)
		return
	}

	newParams := url.Values{}
	if state != "" {
		newParams.Set("state", state)
	}

	newParams.Set("code", issuedEvent.AuthorizationCode)

	uri := fmt.Sprintf("%s?%s", redirectURI, newParams.Encode())
	http.Redirect(w, r, uri, http.StatusFound)
}

func (a *webApp) handleImplicitGrant(w http.ResponseWriter, r *http.Request) {
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	state := r.Form.Get("state")
	scope := r.Form.Get("scope")

	userID, err := a.projections.emailToUserID.GetUserID(username)
	if err != nil {
		errorRedirect(w, r, redirectURI, "access_denied", state)
		return
	}

	events := SavedEvents(a.goAuth2App.Dispatch(goauth2.RequestAccessTokenViaImplicitGrant{
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Username:    username,
		Password:    password,
	}))
	var issuedEvent goauth2.AccessTokenWasIssuedToUserViaImplicitGrant
	if !events.Get(&issuedEvent) {
		if events.ContainsAny(
			&goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationID{},
			&goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationRedirectURI{},
		) {
			writeInvalidRequestResponse(w)
			return
		}

		errorRedirect(w, r, redirectURI, "access_denied", state)
		return
	}

	newParams := url.Values{}
	if state != "" {
		newParams.Set("state", state)
	}

	newParams.Set("access_token", accessTokenTODO)
	newParams.Set("expires_at", strconv.Itoa(expiresAtTODO))
	newParams.Set("scope", scope)
	newParams.Set("token_type", "Bearer")

	uri := fmt.Sprintf("%s#%s", redirectURI, newParams.Encode())
	http.Redirect(w, r, uri, http.StatusFound)
}

// AccessTokenResponse holds the JSON response for an access token.
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresAt    int64  `json:"expires_at"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (a *webApp) token(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		writeInvalidClientResponse(w)
		return
	}

	err := r.ParseForm()
	if err != nil {
		writeInvalidRequestResponse(w)
		return
	}

	grantType := r.Form.Get("grant_type")
	scope := r.Form.Get("scope")

	switch grantType {
	case "client_credentials":
		a.handleClientCredentialsGrant(w, clientID, clientSecret, scope)

	case "password":
		a.handleROPCGrant(w, r, clientID, clientSecret, scope)

	case "refresh_token":
		a.handleRefreshTokenGrant(w, r, clientID, clientSecret, scope)

	case "authorization_code":
		a.handleAuthorizationCodeTokenGrant(w, r, clientID, clientSecret)

	default:
		writeUnsupportedGrantTypeResponse(w)
	}
}

func (a *webApp) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientID, clientSecret, scope string) {
	refreshToken := r.Form.Get("refresh_token")

	events := SavedEvents(a.goAuth2App.Dispatch(goauth2.RequestAccessTokenViaRefreshTokenGrant{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}))

	var accessTokenEvent goauth2.AccessTokenWasIssuedToUserViaRefreshTokenGrant
	if !events.Get(&accessTokenEvent) {
		writeInvalidGrantResponse(w)
		return
	}

	var nextRefreshToken string
	var refreshTokenEvent goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant
	if events.Get(&refreshTokenEvent) {
		nextRefreshToken = refreshTokenEvent.NextRefreshToken
	}

	writeJSONResponse(w, AccessTokenResponse{
		AccessToken:  "61272356284f4340b2b1f3f1400ad4d9",
		ExpiresAt:    accessTokenEvent.ExpiresAt,
		TokenType:    "Bearer",
		RefreshToken: nextRefreshToken,
		Scope:        accessTokenEvent.Scope,
	})
	return
}

func (a *webApp) handleROPCGrant(w http.ResponseWriter, r *http.Request, clientID, clientSecret, scope string) {
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	userID, err := a.projections.emailToUserID.GetUserID(username)
	if err != nil {
		writeInvalidGrantResponse(w)
		return
	}

	events := SavedEvents(a.goAuth2App.Dispatch(goauth2.RequestAccessTokenViaROPCGrant{
		UserID:       userID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
		Scope:        scope,
	}))
	var accessTokenEvent goauth2.AccessTokenWasIssuedToUserViaROPCGrant
	if !events.Get(&accessTokenEvent) {
		if events.Contains(&goauth2.RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{}) {
			writeInvalidClientResponse(w)
			return
		}

		writeInvalidGrantResponse(w)
		return
	}

	var refreshToken string
	var refreshTokenEvent goauth2.RefreshTokenWasIssuedToUserViaROPCGrant
	if events.Get(&refreshTokenEvent) {
		refreshToken = refreshTokenEvent.RefreshToken
	}

	writeJSONResponse(w, AccessTokenResponse{
		AccessToken:  accessTokenTODO,
		ExpiresAt:    accessTokenEvent.ExpiresAt,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Scope:        accessTokenEvent.Scope,
	})
	return
}

func (a *webApp) handleClientCredentialsGrant(w http.ResponseWriter, clientID, clientSecret, scope string) {
	events := SavedEvents(a.goAuth2App.Dispatch(goauth2.RequestAccessTokenViaClientCredentialsGrant{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}))
	var accessTokenIssuedEvent goauth2.AccessTokenWasIssuedToClientApplicationViaClientCredentialsGrant
	if !events.Get(&accessTokenIssuedEvent) {
		writeInvalidClientResponse(w)
		return
	}

	writeJSONResponse(w, AccessTokenResponse{
		AccessToken: accessTokenTODO,
		ExpiresAt:   accessTokenIssuedEvent.ExpiresAt,
		TokenType:   "Bearer",
		Scope:       accessTokenIssuedEvent.Scope,
	})
	return
}

func (a *webApp) handleAuthorizationCodeTokenGrant(w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	authorizationCode := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")

	events := SavedEvents(a.goAuth2App.Dispatch(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
		AuthorizationCode: authorizationCode,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		RedirectURI:       redirectURI,
	}))

	var accessTokenIssuedEvent goauth2.AccessTokenWasIssuedToUserViaAuthorizationCodeGrant
	if !events.Get(&accessTokenIssuedEvent) {
		if events.ContainsAny(
			&goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{},
			&goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationSecret{},
		) {
			writeInvalidClientResponse(w)
			return
		}

		writeInvalidGrantResponse(w)
		return
	}

	var refreshToken string
	var refreshTokenIssuedEvent goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant
	if events.Get(&refreshTokenIssuedEvent) {
		refreshToken = refreshTokenIssuedEvent.RefreshToken
	}

	writeJSONResponse(w, AccessTokenResponse{
		AccessToken:  accessTokenTODO,
		ExpiresAt:    accessTokenIssuedEvent.ExpiresAt,
		TokenType:    "Bearer",
		Scope:        accessTokenIssuedEvent.Scope,
		RefreshToken: refreshToken,
	})
	return
}

func (a *webApp) renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	baseTemplateName := path.Base(templateName)
	tmpl, err := template.New(baseTemplateName).Funcs(funcMap).ParseFS(a.templateFS, "templates/layout/*.gohtml", "templates/"+templateName)
	if err != nil {
		log.Printf("unable to parse template %s: %v", templateName, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("unable to render template %s: %v", templateName, err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeInvalidRequestResponse(w http.ResponseWriter) {
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func writeInternalServerErrorResponse(w http.ResponseWriter) {
	http.Error(w, "invalid request", http.StatusInternalServerError)
}

func writeInvalidClientResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	writeJSONResponse(w, errorResponse{Error: "invalid_client"})
}

func writeInvalidGrantResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	writeJSONResponse(w, errorResponse{Error: "invalid_grant"})
}

func writeUnsupportedGrantTypeResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	writeJSONResponse(w, errorResponse{Error: "unsupported_grant_type"})
}

func writeJSONResponse(w http.ResponseWriter, jsonBody interface{}) {
	bytes, err := json.Marshal(jsonBody)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(bytes)
}

func errorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, errorMessage, state string) {
	query := url.Values{}
	query.Set("error", errorMessage)

	if state != "" {
		query.Set("state", state)
	}
	uri := fmt.Sprintf("%s?%s", redirectURI, query.Encode())
	http.Redirect(w, r, uri, http.StatusFound)
}

func cache30Days(s http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		thirtyDays := time.Hour * 24 * 30
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", thirtyDays))
		s.ServeHTTP(w, r)
	})
}
