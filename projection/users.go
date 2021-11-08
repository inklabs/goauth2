package projection

import (
	"sort"
	"sync"

	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
)

type user struct {
	UserID                      string
	Username                    string
	GrantingUserID              string
	CreateTimestamp             uint64
	IsAdmin                     bool
	CanOnboardAdminApplications bool
}

type Users struct {
	mu    sync.RWMutex
	users map[string]*user
}

func NewUsers() *Users {
	return &Users{
		users: make(map[string]*user),
	}
}

func (a *Users) Accept(record *rangedb.Record) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch event := record.Data.(type) {

	case *goauth2.UserWasOnBoarded:
		a.users[event.UserID] = &user{
			UserID:          event.UserID,
			Username:        event.Username,
			GrantingUserID:  event.GrantingUserID,
			CreateTimestamp: record.InsertTimestamp,
		}

	case *goauth2.UserWasGrantedAdministratorRole:
		if a.userExists(event.UserID) {
			a.users[event.UserID].IsAdmin = true
		}

	case *goauth2.UserWasAuthorizedToOnBoardClientApplications:
		if a.userExists(event.UserID) {
			a.users[event.UserID].CanOnboardAdminApplications = true
		}

	}
}

// GetAll returns users sorted by most recent creation timestamp
func (a *Users) GetAll() []*user {
	a.mu.RLock()

	var users []*user
	for _, user := range a.users {
		users = append(users, user)
	}

	a.mu.RUnlock()

	sort.SliceStable(users, func(i, j int) bool {
		return users[i].CreateTimestamp >= users[j].CreateTimestamp
	})

	return users
}

func (a *Users) userExists(userID string) bool {
	_, ok := a.users[userID]
	return ok
}
