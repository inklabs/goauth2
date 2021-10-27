package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"reflect"
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

//go:embed templates
var templateAssets embed.FS

type app struct {
	router          *mux.Router
	templateManager *templatemanager.TemplateManager
	goauth2App      *goauth2.App
	projections     struct {
		emailToUserID      *projection.EmailToUserID
		clientApplications *projection.ClientApplications
	}
}

// Option defines functional option parameters for app.
type Option func(*app)

// WithTemplateFilesystem is a functional option to inject a template loader.
func WithTemplateFilesystem(fileSystem fs.FS) Option {
	return func(app *app) {
		app.templateManager = templatemanager.New(fileSystem)
	}
}

// WithGoauth2App is a functional option to inject a goauth2 application.
func WithGoauth2App(goauth2App *goauth2.App) Option {
	return func(app *app) {
		app.goauth2App = goauth2App
	}
}

// New constructs an app.
func New(options ...Option) (*app, error) {
	goauth2App, err := goauth2.New()
	if err != nil {
		return nil, err
	}

	assets, templateErr := fs.Sub(templateAssets, "templates")
	if templateErr != nil {
		return nil, templateErr
	}

	app := &app{
		templateManager: templatemanager.New(assets),
		goauth2App:      goauth2App,
	}

	for _, option := range options {
		option(app)
	}

	app.initRoutes()
	err = app.initProjections()
	if err != nil {
		return nil, err
	}

	return app, nil
}

func (a *app) initRoutes() {
	a.router = mux.NewRouter().StrictSlash(true)
	a.router.HandleFunc("/authorize", a.authorize)
	a.router.HandleFunc("/login", a.login)
	a.router.HandleFunc("/token", a.token)
	a.router.HandleFunc("/client-applications", a.listClientApplications)
}

func (a *app) initProjections() error {
	a.projections.emailToUserID = projection.NewEmailToUserID()
	a.projections.clientApplications = projection.NewClientApplications()

	return a.goauth2App.SubscribeAndReplay(
		a.projections.emailToUserID,
		a.projections.clientApplications,
	)
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

	a.renderTemplate(w, "login.html", struct {
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
}

func (a *app) listClientApplications(w http.ResponseWriter, _ *http.Request) {
	type ClientApplication struct {
		ClientID        string
		ClientSecret    string
		CreateTimestamp uint64
	}

	var clientApplications []ClientApplication

	for _, clientApplication := range a.projections.clientApplications.GetAll() {
		clientApplications = append(clientApplications, ClientApplication{
			ClientID:        clientApplication.ClientID,
			ClientSecret:    clientApplication.ClientSecret,
			CreateTimestamp: clientApplication.CreateTimestamp,
		})
	}

	a.renderTemplate(w, "client-applications.html", struct {
		ClientApplications []ClientApplication
	}{
		ClientApplications: clientApplications,
	})
}

func (a *app) authorize(w http.ResponseWriter, r *http.Request) {
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

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresAt    int64  `json:"expires_at"`
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

func (a *app) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientID, clientSecret, scope string) {
	refreshToken := r.Form.Get("refresh_token")

	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaRefreshTokenGrant{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}))

	var issuedEvent goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant
	if !events.Get(&issuedEvent) {
		writeInvalidGrantResponse(w)
		return
	}

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken:  "61272356284f4340b2b1f3f1400ad4d9",
		ExpiresAt:    expiresAtTODO,
		TokenType:    "Bearer",
		RefreshToken: issuedEvent.NextRefreshToken,
		Scope:        issuedEvent.Scope,
	})
	return
}

func (a *app) handleROPCGrant(w http.ResponseWriter, r *http.Request, clientID, clientSecret, scope string) {
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

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken:  accessTokenTODO,
		ExpiresAt:    accessTokenEvent.ExpiresAt,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Scope:        accessTokenEvent.Scope,
	})
	return
}

func (a *app) handleClientCredentialsGrant(w http.ResponseWriter, clientID, clientSecret, scope string) {
	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaClientCredentialsGrant{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}))
	var accessTokenIssuedEvent goauth2.AccessTokenWasIssuedToClientApplicationViaClientCredentialsGrant
	if !events.Get(&accessTokenIssuedEvent) {
		writeInvalidClientResponse(w)
		return
	}

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken: accessTokenTODO,
		ExpiresAt:   accessTokenIssuedEvent.ExpiresAt,
		TokenType:   "Bearer",
		Scope:       accessTokenIssuedEvent.Scope,
	})
	return
}

func (a *app) handleAuthorizationCodeTokenGrant(w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	authorizationCode := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")

	events := SavedEvents(a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
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

	scope := accessTokenIssuedEvent.Scope

	var refreshToken string
	var refreshTokenIssuedEvent goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant
	if events.Get(&refreshTokenIssuedEvent) {
		refreshToken = refreshTokenIssuedEvent.RefreshToken
	}

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken:  accessTokenTODO,
		ExpiresAt:    expiresAtTODO,
		TokenType:    "Bearer",
		Scope:        scope,
		RefreshToken: refreshToken,
	})
	return
}

func (a *app) renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	err := a.templateManager.RenderTemplate(w, templateName, data)

	if err != nil {
		log.Println(err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeInvalidRequestResponse(w http.ResponseWriter) {
	http.Error(w, "invalid request", http.StatusBadRequest)
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

// SavedEvents contains events that have been persisted to the event store.
type SavedEvents []rangedb.Event

// Contains returns true if all events are found.
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

// ContainsAny returns true if any events are found.
func (l *SavedEvents) ContainsAny(events ...rangedb.Event) bool {
	for _, event := range events {
		for _, savedEvent := range *l {
			if event.EventType() == savedEvent.EventType() {
				return true
			}
		}
	}

	return false
}

// Get returns true if the event was found and stores the result
// in the value pointed to by event. If it is not found, Get
// returns false.
func (l *SavedEvents) Get(event rangedb.Event) bool {
	for _, savedEvent := range *l {
		if event.EventType() == savedEvent.EventType() {
			eventVal := reflect.ValueOf(event)
			savedEventVal := reflect.ValueOf(savedEvent)

			if savedEventVal.Kind() == reflect.Ptr {
				savedEventVal = savedEventVal.Elem()
			}

			if savedEventVal.Type().AssignableTo(eventVal.Type().Elem()) {
				eventVal.Elem().Set(savedEventVal)
				return true
			}
		}
	}

	return false
}
