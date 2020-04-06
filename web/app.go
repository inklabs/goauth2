package web

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/inklabs/goauth2/web/pkg/templateloader"
	"github.com/inklabs/goauth2/web/pkg/templateloader/provider/statikloader"
	"github.com/inklabs/goauth2/web/pkg/templatemanager"
	_ "github.com/inklabs/goauth2/web/statik"
)

//go:generate go run github.com/rakyll/statik -src ./templates

type app struct {
	router          *mux.Router
	templateManager *templatemanager.TemplateManager
}

// Option defines functional option parameters for app.
type Option func(*app)

// WithTemplateLoader is a functional option to inject a template loader.
func WithTemplateLoader(templateLoader templateloader.TemplateLoader) Option {
	return func(app *app) {
		app.templateManager = templatemanager.New(templateLoader)
	}
}

// New constructs an app.
func New(options ...Option) *app {
	app := &app{
		router:          nil,
		templateManager: templatemanager.New(statikloader.New()),
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
