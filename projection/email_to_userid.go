package projection

import (
	"fmt"
	"sync"

	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
)

// EmailToUserID projection.
type EmailToUserID struct {
	mu            sync.RWMutex
	emailToUserID map[string]string
}

// NewEmailToUserID constructs an EmailToUserID projection.
func NewEmailToUserID() *EmailToUserID {
	return &EmailToUserID{
		emailToUserID: make(map[string]string),
	}
}

// Accept receives a rangedb.Record.
func (a *EmailToUserID) Accept(record *rangedb.Record) {
	event, ok := record.Data.(*goauth2.UserWasOnBoarded)
	if ok {
		a.mu.Lock()
		defer a.mu.Unlock()

		a.emailToUserID[event.Username] = event.UserID
	}
}

// GetUserID returns a userID by email or ErrUserNotFound.
func (a *EmailToUserID) GetUserID(email string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	userID, ok := a.emailToUserID[email]
	if !ok {
		return "", ErrUserNotFound
	}

	return userID, nil
}

// ErrUserNotFound is a defined error for missing user.
var ErrUserNotFound = fmt.Errorf("user not found")
