package web

import (
	"fmt"
	"net/http"
)

const (
	sessionName     = "goa2"
	flashMessageKey = "flash.message"
	flashErrorKey   = "flash.error"
)

func (a *webApp) FlashError(w http.ResponseWriter, r *http.Request, format string, vars ...interface{}) {
	a.flashMessage(w, r, flashErrorKey, fmt.Sprintf(format, vars...))
}

func (a *webApp) FlashMessage(w http.ResponseWriter, r *http.Request, format string, vars ...interface{}) {
	a.flashMessage(w, r, flashMessageKey, fmt.Sprintf(format, vars...))
}

func (a *webApp) flashMessage(w http.ResponseWriter, r *http.Request, key, message string) {
	session, _ := a.sessionStore.Get(r, sessionName)
	session.AddFlash(message, key)
	_ = session.Save(r, w)
}

func (a *webApp) getFlashMessageVars(w http.ResponseWriter, r *http.Request) flashMessageVars {
	session, _ := a.sessionStore.Get(r, sessionName)
	fErrors := session.Flashes(flashErrorKey)
	fMessages := session.Flashes(flashMessageKey)

	var flashErrors, flashMessages []string
	for _, flash := range fErrors {
		flashErrors = append(flashErrors, flash.(string))
	}
	for _, flash := range fMessages {
		flashMessages = append(flashMessages, flash.(string))
	}

	if len(fErrors) > 0 || len(fMessages) > 0 {
		_ = session.Save(r, w)
	}

	return flashMessageVars{
		Errors:   flashErrors,
		Messages: flashMessages,
	}
}
