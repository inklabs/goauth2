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
	tokenGenerator                          TokenGenerator
}

func newResourceOwner(records <-chan *rangedb.Record, tokenGenerator TokenGenerator) *resourceOwner {
	aggregate := &resourceOwner{
		tokenGenerator: tokenGenerator,
	}

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

	case *UserWasOnBoarded:
		a.IsOnBoarded = true
		a.Username = e.Username
		a.PasswordHash = e.PasswordHash

	case *UserWasAuthorizedToOnBoardClientApplications:
		a.IsAuthorizedToOnboardClientApplications = true

	case *UserWasGrantedAdministratorRole:
		a.IsAdministrator = true

	}
}

func (a *resourceOwner) Handle(command Command) {
	switch c := command.(type) {

	case OnBoardUser:
		if a.IsOnBoarded {
			a.emit(OnBoardUserWasRejectedDueToExistingUser{
				UserID: c.UserID,
			})
			return
		}

		if securepass.IsInsecure(c.Password) {
			a.emit(OnBoardUserWasRejectedDueToInsecurePassword{
				UserID: c.UserID,
			})
			return
		}

		a.emit(UserWasOnBoarded{
			UserID:       c.UserID,
			Username:     c.Username,
			PasswordHash: GeneratePasswordHash(c.Password),
		})

	case GrantUserAdministratorRole:
		if !a.IsOnBoarded {
			a.emit(GrantUserAdministratorRoleWasRejectedDueToMissingTargetUser{
				UserID:         c.UserID,
				GrantingUserID: c.GrantingUserID,
			})
			return
		}

		a.emit(UserWasGrantedAdministratorRole{
			UserID:         c.UserID,
			GrantingUserID: c.GrantingUserID,
		})

	case AuthorizeUserToOnBoardClientApplications:
		if !a.IsOnBoarded {
			a.emit(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingTargetUser{
				UserID:            c.UserID,
				AuthorizingUserID: c.AuthorizingUserID,
			})
			return
		}

		a.emit(UserWasAuthorizedToOnBoardClientApplications{
			UserID:            c.UserID,
			AuthorizingUserID: c.AuthorizingUserID,
		})

	case RequestAccessTokenViaImplicitGrant:
		if !a.IsOnBoarded {
			a.emit(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUser{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			})
			return
		}

		if !a.IsPasswordValid(c.Password) {
			a.emit(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUserPassword{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			})
			return
		}

		a.emit(AccessTokenWasIssuedToUserViaImplicitGrant{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})

	case RequestAccessTokenViaROPCGrant:
		if !a.IsOnBoarded {
			a.emit(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUser{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			})
			return
		}

		if !a.IsPasswordValid(c.Password) {
			a.emit(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUserPassword{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			})
			return
		}

		token, err := a.tokenGenerator.New()
		if err != nil {
			// TODO: emit error
			return
		}

		a.emit(
			AccessTokenWasIssuedToUserViaROPCGrant{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			},
			RefreshTokenWasIssuedToUserViaROPCGrant{
				UserID:       c.UserID,
				ClientID:     c.ClientID,
				RefreshToken: token,
			},
		)

	}
}

func (a *resourceOwner) emit(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.PendingEvents = append(a.PendingEvents, events...)
}

func (a *resourceOwner) IsPasswordValid(password string) bool {
	return VerifyPassword(a.PasswordHash, password)
}
