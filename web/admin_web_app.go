package web

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"

	"github.com/inklabs/goauth2"
)

// AdminUserIDTODO temporary ID that will be replaced with a value from a JWT or session.
const AdminUserIDTODO = "873aeb9386724213b4c1410bce9f838c"

func (a *webApp) addAdminRoutes(r *mux.Router) {
	csrfMiddleware := csrf.Protect(
		a.csrfAuthKey,
		csrf.Secure(false),
		csrf.SameSite(csrf.SameSiteStrictMode),
	)

	admin := r.PathPrefix("/admin").Subrouter()
	admin.HandleFunc("/login", a.showAdminLogin).Methods(http.MethodGet)
	admin.HandleFunc("/add-user", a.showAddUser).Methods(http.MethodGet)
	admin.HandleFunc("/add-user", a.submitAddUser).Methods(http.MethodPost)
	admin.HandleFunc("/list-users", a.listUsers)
	admin.HandleFunc("/list-client-applications", a.listClientApplications)
	admin.Use(csrfMiddleware)
}

type clientApplication struct {
	ClientID        string
	ClientSecret    string
	CreateTimestamp uint64
}

type listClientApplicationsTemplateVars struct {
	flashMessageVars
	ClientApplications []clientApplication
}

func (a *webApp) listClientApplications(w http.ResponseWriter, _ *http.Request) {

	var clientApplications []clientApplication

	for _, ca := range a.projections.clientApplications.GetAll() {
		clientApplications = append(clientApplications, clientApplication{
			ClientID:        ca.ClientID,
			ClientSecret:    ca.ClientSecret,
			CreateTimestamp: ca.CreateTimestamp,
		})
	}

	a.renderTemplate(w, "admin/list-client-applications.gohtml", listClientApplicationsTemplateVars{
		ClientApplications: clientApplications,
	})
}

type flashMessageVars struct {
	Errors   []string
	Messages []string
}

type resourceOwnerUser struct {
	UserID                      string
	Username                    string
	GrantingUserID              string
	CreateTimestamp             uint64
	IsAdmin                     bool
	CanOnboardAdminApplications bool
}

type listUsersTemplateVars struct {
	flashMessageVars
	Users []resourceOwnerUser
}

func (a *webApp) listUsers(w http.ResponseWriter, r *http.Request) {

	var users []resourceOwnerUser

	for _, user := range a.projections.users.GetAll() {
		users = append(users, resourceOwnerUser{
			UserID:                      user.UserID,
			Username:                    user.Username,
			GrantingUserID:              user.GrantingUserID,
			CreateTimestamp:             user.CreateTimestamp,
			IsAdmin:                     user.IsAdmin,
			CanOnboardAdminApplications: user.CanOnboardAdminApplications,
		})
	}

	a.renderTemplate(w, "admin/list-users.gohtml", listUsersTemplateVars{
		Users:            users,
		flashMessageVars: a.getFlashMessageVars(w, r),
	})
}

type adminLoginTemplateVars struct {
	flashMessageVars
	Username  string
	CSRFField template.HTML
}

func (a *webApp) showAdminLogin(w http.ResponseWriter, r *http.Request) {
	a.renderTemplate(w, "admin/login.gohtml", adminLoginTemplateVars{
		Username:         "", // TODO: Add when form post fails on redirect
		CSRFField:        csrf.TemplateField(r),
		flashMessageVars: a.getFlashMessageVars(w, r),
	})
}

type addUserTemplateVars struct {
	flashMessageVars
	Username  string
	CSRFField template.HTML
}

func (a *webApp) showAddUser(w http.ResponseWriter, r *http.Request) {
	a.renderTemplate(w, "admin/add-user.gohtml", addUserTemplateVars{
		Username:         "", // TODO: Add when form post fails on redirect
		CSRFField:        csrf.TemplateField(r),
		flashMessageVars: a.getFlashMessageVars(w, r),
	})
}

func (a *webApp) submitAddUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeInvalidRequestResponse(w)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")
	// confirmPassword := r.Form.Get("confirm_password")

	if username == "" || password == "" {
		redirectURI := url.URL{
			Path: "/admin/add-user",
		}
		a.FlashError(w, r, "username or password are required")
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	userID := a.uuidGenerator.New()
	grantingUserID := AdminUserIDTODO // TODO: Get grantingUserID from JWT
	events := SavedEvents(a.goAuth2App.Dispatch(goauth2.OnBoardUser{
		UserID:         userID,
		Username:       username,
		Password:       password,
		GrantingUserID: grantingUserID,
	}))
	var userWasOnBoarded goauth2.UserWasOnBoarded
	if !events.Get(&userWasOnBoarded) {
		redirectURI := url.URL{
			Path: "/admin/add-user",
		}
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	a.FlashMessage(w, r, "User (%s) was added", username)

	uri := url.URL{
		Path: "/admin/list-users",
	}
	http.Redirect(w, r, uri.String(), http.StatusFound)
}
