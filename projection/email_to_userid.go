package projection

import (
	"fmt"

	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
)

type EmailToUserID struct {
	emailToUserID map[string]string
}

func NewEmailToUserID() *EmailToUserID {
	return &EmailToUserID{
		emailToUserID: make(map[string]string),
	}
}

func (a *EmailToUserID) Accept(record *rangedb.Record) {
	event, ok := record.Data.(*goauth2.UserWasOnBoarded)
	if ok {
		a.emailToUserID[event.Username] = event.UserID
	}
}

func (a *EmailToUserID) GetUserID(email string) (string, error) {
	userID, ok := a.emailToUserID[email]
	if !ok {
		return "", UserNotFound
	}

	return userID, nil
}

var UserNotFound = fmt.Errorf("user not found")
