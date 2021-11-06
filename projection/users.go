package projection

import (
	"sort"

	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
)

type user struct {
	UserID                      string
	Username                    string
	CreateTimestamp             uint64
	IsAdmin                     bool
	CanOnboardAdminApplications bool
}

type Users struct {
	users map[string]*user
}

func NewUsers() *Users {
	return &Users{
		users: make(map[string]*user),
	}
}

func (a *Users) Accept(record *rangedb.Record) {
	switch event := record.Data.(type) {

	case *goauth2.UserWasOnBoarded:
		a.users[event.UserID] = &user{
			UserID:          event.UserID,
			Username:        event.Username,
			CreateTimestamp: record.InsertTimestamp,
		}

	case *goauth2.UserWasGrantedAdministratorRole:
		a.users[event.UserID].IsAdmin = true

	case *goauth2.UserWasAuthorizedToOnBoardClientApplications:
		a.users[event.UserID].CanOnboardAdminApplications = true

	}
}

// GetAll returns users sorted by most recent creation timestamp
func (a *Users) GetAll() []*user {
	var users []*user
	for _, user := range a.users {
		users = append(users, user)
	}

	sort.SliceStable(users, func(i, j int) bool {
		return users[i].CreateTimestamp >= users[j].CreateTimestamp
	})

	return users
}
