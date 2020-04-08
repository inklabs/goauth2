package goauth2

import (
	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2/pkg/securepass"
)

type resourceOwner struct {
	IsOnBoarded                             bool
	Username                                string
	PasswordHash                            string
	PendingEvents                           []rangedb.Event
	IsAdministrator                         bool
	IsAuthorizedToOnboardClientApplications bool
}

func newResourceOwner(records <-chan *rangedb.Record) *resourceOwner {
	aggregate := &resourceOwner{}

	for record := range records {
		if event, ok := record.Data.(rangedb.Event); ok {
			aggregate.apply(event)
		}
	}

	return aggregate
}

func (a *resourceOwner) GetPendingEvents() []rangedb.Event {
	return a.PendingEvents
}

func (a *resourceOwner) apply(event rangedb.Event) {
	switch e := event.(type) {

	case error:
	case *UserWasOnBoarded:
		a.IsOnBoarded = true
		a.Username = e.Username
		a.PasswordHash = e.PasswordHash

	}
}

func (a *resourceOwner) Handle(command Command) {
	switch c := command.(type) {

	case OnBoardUser:
		if a.IsOnBoarded {
			a.Emit(OnBoardUserWasRejectedDueToExistingUser{
				UserID: c.UserID,
			})
			return
		}

		if securepass.IsInsecure(c.Password) {
			a.Emit(OnBoardUserWasRejectedDueToInsecurePassword{
				UserID: c.UserID,
			})
			return
		}

		a.Emit(UserWasOnBoarded{
			UserID:       c.UserID,
			Username:     c.Username,
			PasswordHash: GeneratePasswordHash(c.Password),
		})

	}
}

func (a *resourceOwner) Emit(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.PendingEvents = append(a.PendingEvents, events...)
}
