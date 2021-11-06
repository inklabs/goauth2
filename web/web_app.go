package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
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
)

const (
	accessTokenTODO = "f5bb89d486ee458085e476871b177ff4"
	expiresAtTODO   = 1574371565
)

//go:embed static
var staticAssets embed.FS

//go:embed templates
var templates embed.FS

const defaultHost = "0.0.0.0:8080"

type webApp struct {
	router      *mux.Router
	templateFS  fs.FS
	goAuth2App  *goauth2.App
	host        string
	projections struct {
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

// WithGoAuth2App is a functional option to inject a goauth2 application.
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

// New constructs an webApp.
func New(options ...Option) (*webApp, error) {
	goAuth2App, err := goauth2.New()
	if err != nil {
		return nil, err
	}

	app := &webApp{
		templateFS: templates,
		goAuth2App: goAuth2App,
		host:       defaultHost,
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

func (a *webApp) initRoutes() {
	a.router = mux.NewRouter().StrictSlash(true)
	a.router.HandleFunc("/authorize", a.authorize)
	a.router.HandleFunc("/login", a.login)
	a.router.HandleFunc("/token", a.token)
	a.router.HandleFunc("/list-client-applications", a.listClientApplications)
	a.router.HandleFunc("/list-users", a.listUsers)
	a.router.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticAssets)))
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
	clientId := params.Get("client_id")
	redirectURI := params.Get("redirect_uri")
	responseType := params.Get("response_type")
	state := params.Get("state")
	scope := params.Get("scope")

	a.renderTemplate(w, "login.gohtml", struct {
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

type ClientApplication struct {
	ClientID        string
	ClientSecret    string
	CreateTimestamp uint64
}

type listClientApplicationsTemplateVars struct {
	ClientApplications []ClientApplication
}

func (a *webApp) listClientApplications(w http.ResponseWriter, _ *http.Request) {

	var clientApplications []ClientApplication

	for _, clientApplication := range a.projections.clientApplications.GetAll() {
		clientApplications = append(clientApplications, ClientApplication{
			ClientID:        clientApplication.ClientID,
			ClientSecret:    clientApplication.ClientSecret,
			CreateTimestamp: clientApplication.CreateTimestamp,
		})
	}

	a.renderTemplate(w, "list-client-applications.gohtml", listClientApplicationsTemplateVars{
		ClientApplications: clientApplications,
	})
}

type User struct {
	UserID                      string
	Username                    string
	CreateTimestamp             uint64
	IsAdmin                     bool
	CanOnboardAdminApplications bool
}

type listUsersTemplateVars struct {
	Users []User
}

func (a *webApp) listUsers(w http.ResponseWriter, _ *http.Request) {

	var users []User

	for _, user := range a.projections.users.GetAll() {
		users = append(users, User{
			UserID:                      user.UserID,
			Username:                    user.Username,
			CreateTimestamp:             user.CreateTimestamp,
			IsAdmin:                     user.IsAdmin,
			CanOnboardAdminApplications: user.CanOnboardAdminApplications,
		})
	}

	a.renderTemplate(w, "list-users.gohtml", listUsersTemplateVars{
		Users: users,
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

	writeJsonResponse(w, AccessTokenResponse{
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

	writeJsonResponse(w, AccessTokenResponse{
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

	writeJsonResponse(w, AccessTokenResponse{
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

	writeJsonResponse(w, AccessTokenResponse{
		AccessToken:  accessTokenTODO,
		ExpiresAt:    accessTokenIssuedEvent.ExpiresAt,
		TokenType:    "Bearer",
		Scope:        accessTokenIssuedEvent.Scope,
		RefreshToken: refreshToken,
	})
	return
}

func (a *webApp) renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	tmpl, err := template.New(templateName).Funcs(FuncMap).ParseFS(a.templateFS, "templates/layout/*.gohtml", "templates/"+templateName)
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
