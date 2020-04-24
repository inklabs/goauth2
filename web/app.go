package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/projection"
	"github.com/inklabs/goauth2/web/pkg/templatemanager"
)

const (
	accessTokenTODO = "f5bb89d486ee458085e476871b177ff4"
	expiresAtTODO   = 1574371565
)

//go:generate go run github.com/shurcooL/vfsgen/cmd/vfsgendev -source="github.com/inklabs/goauth2/web".TemplateAssets

type app struct {
	router          *mux.Router
	templateManager *templatemanager.TemplateManager
	goauth2App      *goauth2.App
	projections     struct {
		emailToUserID *projection.EmailToUserID
	}
}

//Option defines functional option parameters for app.
type Option func(*app)

//WithTemplateFilesystem is a functional option to inject a template loader.
func WithTemplateFilesystem(fileSystem http.FileSystem) Option {
	return func(app *app) {
		app.templateManager = templatemanager.New(fileSystem)
	}
}

//WithGoauth2App is a functional option to inject a goauth2 application.
func WithGoauth2App(goauth2App *goauth2.App) Option {
	return func(app *app) {
		app.goauth2App = goauth2App
	}
}

//New constructs an app.
func New(options ...Option) *app {
	app := &app{
		templateManager: templatemanager.New(TemplateAssets),
		goauth2App:      goauth2.New(),
	}

	for _, option := range options {
		option(app)
	}

	app.initRoutes()
	app.initProjections()

	return app
}

func (a *app) initRoutes() {
	a.router = mux.NewRouter().StrictSlash(true)
	a.router.HandleFunc("/authorize", a.authorize)
	a.router.HandleFunc("/login", a.login)
	a.router.HandleFunc("/token", a.token)
}

func (a *app) initProjections() {
	a.projections.emailToUserID = projection.NewEmailToUserID()
	a.goauth2App.SubscribeAndReplay(a.projections.emailToUserID)
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	clientId := params.Get("client_id")
	redirectURI := params.Get("redirect_uri")
	responseType := params.Get("response_type")
	state := params.Get("state")
	scope := params.Get("scope")

	err := a.templateManager.RenderTemplate(w, "login.html", struct {
		ClientId     string
		RedirectURI  string
		ResponseType string
		Scope        string
		State        string
	}{
		ClientId:     clientId,
		RedirectURI:  redirectURI,
		ResponseType: responseType,
		Scope:        scope,
		State:        state,
	})
	if err != nil {
		log.Println(err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

func (a *app) authorize(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
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

func (a *app) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
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

	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrant{
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Username:    username,
		Password:    password,
		Scope:       scope,
	}))
	authorizationEvent, err := events.Get(&goauth2.AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant{})
	if err != nil {
		errorRedirect(w, r, redirectURI, "access_denied", state)
		return
	}

	newParams := url.Values{}
	if state != "" {
		newParams.Set("state", state)
	}

	issuedEvent := authorizationEvent.(goauth2.AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant)
	newParams.Set("code", issuedEvent.AuthorizationCode)

	uri := fmt.Sprintf("%s?%s", redirectURI, newParams.Encode())
	http.Redirect(w, r, uri, http.StatusFound)
}

func (a *app) handleImplicitGrant(w http.ResponseWriter, r *http.Request) {
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

	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaImplicitGrant{
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Username:    username,
		Password:    password,
	}))
	accessTokenEvent, err := events.Get(&goauth2.AccessTokenWasIssuedToUserViaImplicitGrant{})
	if err != nil {
		errorRedirect(w, r, redirectURI, "access_denied", state)
		return
	}

	issuedEvent := accessTokenEvent.(goauth2.AccessTokenWasIssuedToUserViaImplicitGrant)

	newParams := url.Values{}
	if state != "" {
		newParams.Set("state", state)
	}

	newParams.Set("access_token", accessTokenTODO)
	newParams.Set("expires_at", strconv.Itoa(expiresAtTODO))
	newParams.Set("scope", scope)
	newParams.Set("token_type", "Bearer")
	_ = issuedEvent

	uri := fmt.Sprintf("%s#%s", redirectURI, newParams.Encode())
	http.Redirect(w, r, uri, http.StatusFound)
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresAt    int    `json:"expires_at"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (a *app) token(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		writeInvalidClientResponse(w)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
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

	default:
		writeUnsupportedGrantTypeResponse(w)
	}
}

func (a *app) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientID string, clientSecret string, scope string) {
	refreshToken := r.Form.Get("refresh_token")

	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaRefreshTokenGrant{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}))

	refreshTokenEvent, err := events.Get(&goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant{})
	if err != nil {
		writeInvalidGrantResponse(w)
		return
	}
	issuedRefreshTokenEvent := refreshTokenEvent.(goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant)

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken:  "61272356284f4340b2b1f3f1400ad4d9",
		ExpiresAt:    expiresAtTODO,
		TokenType:    "Bearer",
		RefreshToken: issuedRefreshTokenEvent.NextRefreshToken,
		Scope:        issuedRefreshTokenEvent.Scope,
	})
	return
}

func (a *app) handleROPCGrant(w http.ResponseWriter, r *http.Request, clientID string, clientSecret string, scope string) {
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	userID, err := a.projections.emailToUserID.GetUserID(username)
	if err != nil {
		writeInvalidGrantResponse(w)
		return
	}

	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaROPCGrant{
		UserID:       userID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
		Scope:        scope,
	}))
	if !events.Contains(&goauth2.AccessTokenWasIssuedToUserViaROPCGrant{}) {
		if events.Contains(&goauth2.RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{}) {
			writeInvalidClientResponse(w)
			return
		}

		writeInvalidGrantResponse(w)
		return
	}

	var refreshToken string

	refreshTokenEvent, err := events.Get(&goauth2.RefreshTokenWasIssuedToUserViaROPCGrant{})
	if err == nil {
		refreshToken = refreshTokenEvent.(goauth2.RefreshTokenWasIssuedToUserViaROPCGrant).RefreshToken
	}

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken:  accessTokenTODO,
		ExpiresAt:    expiresAtTODO,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Scope:        scope,
	})
	return
}

func (a *app) handleClientCredentialsGrant(w http.ResponseWriter, clientID string, clientSecret string, scope string) {
	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaClientCredentialsGrant{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}))
	if !events.Contains(&goauth2.AccessTokenWasIssuedToClientApplicationViaClientCredentialsGrant{}) {
		writeInvalidClientResponse(w)
		return
	}

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken: accessTokenTODO,
		ExpiresAt:   expiresAtTODO,
		TokenType:   "Bearer",
		Scope:       scope,
	})
	return
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeInvalidClientResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	writeJsonResponse(w, errorResponse{Error: "invalid_client"})
}

func writeInvalidGrantResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	writeJsonResponse(w, errorResponse{Error: "invalid_grant"})
}

func writeUnsupportedGrantTypeResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	writeJsonResponse(w, errorResponse{Error: "unsupported_grant_type"})
}

func writeJsonResponse(w http.ResponseWriter, jsonBody interface{}) {
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

//SavedEvents contains events that have been persisted to the event store.
type SavedEvents []rangedb.Event

func (l *SavedEvents) Contains(events ...rangedb.Event) bool {
	var totalFound int
	for _, event := range events {
		for _, savedEvent := range *l {
			if event.EventType() == savedEvent.EventType() {
				totalFound++
				break
			}
		}
	}
	return len(events) == totalFound
}

func (l *SavedEvents) Get(event rangedb.Event) (rangedb.Event, error) {
	for _, savedEvent := range *l {
		if event.EventType() == savedEvent.EventType() {
			return savedEvent, nil
		}
	}

	return nil, EventNotFound
}

var EventNotFound = fmt.Errorf("event not found")
