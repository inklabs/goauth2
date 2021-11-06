package projection

import (
	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
)

type user struct {
	UserID          string
	Username        string
	CreateTimestamp uint64
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
	event, ok := record.Data.(*goauth2.UserWasOnBoarded)
	if ok {
		a.users[event.UserID] = &user{
			UserID:          event.UserID,
			Username:        event.Username,
			CreateTimestamp: record.InsertTimestamp,
		}
	}
}

func (a *Users) GetAll() []*user {
	var users []*user
	for _, user := range a.users {
		users = append(users, user)
	}
	return users
}
