package goauth2

import (
	"time"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"

	"github.com/inklabs/goauth2/pkg/securepass"
)

const authorizationCodeLifetime = 10 * time.Minute

type resourceOwner struct {
	IsOnBoarded                             bool
	Username                                string
	PasswordHash                            string
	PendingEvents                           []rangedb.Event
	IsAdministrator                         bool
	IsAuthorizedToOnboardClientApplications bool
	tokenGenerator                          TokenGenerator
	clock                                   clock.Clock
}

func newResourceOwner(records <-chan *rangedb.Record, tokenGenerator TokenGenerator, clock clock.Clock) *resourceOwner {
	aggregate := &resourceOwner{
		tokenGenerator: tokenGenerator,
		clock:          clock,
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

		token := a.tokenGenerator.New()

		a.emit(
			AccessTokenWasIssuedToUserViaROPCGrant{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			},
			RefreshTokenWasIssuedToUserViaROPCGrant{
				UserID:       c.UserID,
				ClientID:     c.ClientID,
				RefreshToken: token,
				Scope:        c.Scope,
			},
		)

	case RequestAuthorizationCodeViaAuthorizationCodeGrant:
		if !a.IsOnBoarded {
			a.emit(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUser{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			})
			return
		}

		if !a.IsPasswordValid(c.Password) {
			a.emit(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUserPassword{
				UserID:   c.UserID,
				ClientID: c.ClientID,
			})
			return
		}

		authorizationCode := a.tokenGenerator.New()

		expiresAt := a.clock.Now().Add(authorizationCodeLifetime).Unix()

		a.emit(AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant{
			UserID:            c.UserID,
			AuthorizationCode: authorizationCode,
			ExpiresAt:         expiresAt,
		})

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
