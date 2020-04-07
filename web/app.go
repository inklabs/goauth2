package web

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/web/pkg/templatemanager"
)

//go:generate go run github.com/shurcooL/vfsgen/cmd/vfsgendev -source="github.com/inklabs/goauth2/web".TemplateAssets

type app struct {
	router          *mux.Router
	templateManager *templatemanager.TemplateManager
	goauth2App      *goauth2.App
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

	return app
}

func (a *app) initRoutes() {
	a.router = mux.NewRouter().StrictSlash(true)
	a.router.HandleFunc("/login", a.login)
	a.router.HandleFunc("/token", a.token)
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	clientId := params.Get("client_id")
	redirectUri := params.Get("redirect_uri")
	responseType := params.Get("response_type")
	state := params.Get("state")
	scope := params.Get("scope")

	err := a.templateManager.RenderTemplate(w, "login.html", struct {
		ClientId     string
		RedirectUri  string
		ResponseType string
		Scope        string
		State        string
	}{
		ClientId:     clientId,
		RedirectUri:  redirectUri,
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

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

type accessTokenResponse struct {
	UserId       string `json:"user_id,omitempty"`
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

	accessToken := "f5bb89d486ee458085e476871b177ff4"
	refreshToken := "df00e449f5f4489ea2d26e18f0015274"

	switch grantType {
	case "client_credentials":
		events := a.goauth2App.Dispatch(goauth2.RequestAccessTokenViaClientCredentialsGrant{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
		if !events.Contains(&goauth2.AccessTokenWasIssuedToClientApplicationViaClientCredentialsGrant{}) {
			writeInvalidClientResponse(w)
			return
		}

	default:
		writeUnsupportedGrantTypeResponse(w)
		return

	}

	writeJsonResponse(w, accessTokenResponse{
		AccessToken:  accessToken,
		ExpiresAt:    1574371565,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Scope:        scope,
	})
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeInvalidClientResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	writeJsonResponse(w, errorResponse{Error: "invalid_client"})
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
