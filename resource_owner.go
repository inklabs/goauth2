package goauth2

import (
	"time"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"

	"github.com/inklabs/goauth2/pkg/securepass"
)

const (
	authorizationCodeLifetime      = 10 * time.Minute
	authorizationCodeGrantLifetime = 1 * time.Hour
	ropcGrantLifetime              = 1 * time.Hour
)

func ResourceOwnerCommandTypes() []string {
	return []string{
		GrantUserAdministratorRole{}.CommandType(),
		OnBoardUser{}.CommandType(),
		AuthorizeUserToOnBoardClientApplications{}.CommandType(),
		RequestAccessTokenViaImplicitGrant{}.CommandType(),
		RequestAccessTokenViaROPCGrant{}.CommandType(),
		RequestAuthorizationCodeViaAuthorizationCodeGrant{}.CommandType(),
	}
}

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

func newResourceOwner(iter rangedb.RecordIterator, tokenGenerator TokenGenerator, clock clock.Clock) *resourceOwner {
	aggregate := &resourceOwner{
		tokenGenerator: tokenGenerator,
		clock:          clock,
	}

	for iter.Next() {
		if event, ok := iter.Record().Data.(rangedb.Event); ok {
			aggregate.apply(event)
		}
	}

	return aggregate
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

func (a *resourceOwner) GetPendingEvents() []rangedb.Event {
	return a.PendingEvents
}

func (a *resourceOwner) Handle(command Command) {
	switch c := command.(type) {

	case OnBoardUser:
		a.OnBoardUser(c)

	case GrantUserAdministratorRole:
		a.GrantUserAdministratorRole(c)

	case AuthorizeUserToOnBoardClientApplications:
		a.AuthorizeUserToOnBoardClientApplications(c)

	case RequestAccessTokenViaImplicitGrant:
		a.RequestAccessTokenViaImplicitGrant(c)

	case RequestAccessTokenViaROPCGrant:
		a.RequestAccessTokenViaROPCGrant(c)

	case RequestAuthorizationCodeViaAuthorizationCodeGrant:
		a.RequestAuthorizationCodeViaAuthorizationCodeGrant(c)

	}
}

func (a *resourceOwner) OnBoardUser(c OnBoardUser) {
	if a.IsOnBoarded {
		a.raise(OnBoardUserWasRejectedDueToExistingUser{
			UserID: c.UserID,
		})
		return
	}

	if securepass.IsInsecure(c.Password) {
		a.raise(OnBoardUserWasRejectedDueToInsecurePassword{
			UserID: c.UserID,
		})
		return
	}

	a.raise(UserWasOnBoarded{
		UserID:       c.UserID,
		Username:     c.Username,
		PasswordHash: GeneratePasswordHash(c.Password),
	})
}

func (a *resourceOwner) GrantUserAdministratorRole(c GrantUserAdministratorRole) {
	if !a.IsOnBoarded {
		a.raise(GrantUserAdministratorRoleWasRejectedDueToMissingTargetUser{
			UserID:         c.UserID,
			GrantingUserID: c.GrantingUserID,
		})
		return
	}

	a.raise(UserWasGrantedAdministratorRole{
		UserID:         c.UserID,
		GrantingUserID: c.GrantingUserID,
	})
}

func (a *resourceOwner) AuthorizeUserToOnBoardClientApplications(c AuthorizeUserToOnBoardClientApplications) {
	if !a.IsOnBoarded {
		a.raise(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingTargetUser{
			UserID:            c.UserID,
			AuthorizingUserID: c.AuthorizingUserID,
		})
		return
	}

	a.raise(UserWasAuthorizedToOnBoardClientApplications{
		UserID:            c.UserID,
		AuthorizingUserID: c.AuthorizingUserID,
	})
}

func (a *resourceOwner) RequestAccessTokenViaImplicitGrant(c RequestAccessTokenViaImplicitGrant) {
	if !a.IsOnBoarded {
		a.raise(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUser{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return
	}

	if !a.isPasswordValid(c.Password) {
		a.raise(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUserPassword{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return
	}

	a.raise(AccessTokenWasIssuedToUserViaImplicitGrant{
		UserID:   c.UserID,
		ClientID: c.ClientID,
	})
}

func (a *resourceOwner) RequestAccessTokenViaROPCGrant(c RequestAccessTokenViaROPCGrant) {
	if !a.IsOnBoarded {
		a.raise(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUser{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return
	}

	if !a.isPasswordValid(c.Password) {
		a.raise(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUserPassword{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return
	}

	token := a.tokenGenerator.New()
	expiresAt := a.clock.Now().Add(ropcGrantLifetime).Unix()

	a.raise(
		AccessTokenWasIssuedToUserViaROPCGrant{
			UserID:    c.UserID,
			ClientID:  c.ClientID,
			ExpiresAt: expiresAt,
			Scope:     c.Scope,
		},
		RefreshTokenWasIssuedToUserViaROPCGrant{
			UserID:       c.UserID,
			ClientID:     c.ClientID,
			RefreshToken: token,
			Scope:        c.Scope,
		},
	)
}

func (a *resourceOwner) RequestAuthorizationCodeViaAuthorizationCodeGrant(c RequestAuthorizationCodeViaAuthorizationCodeGrant) {
	if !a.IsOnBoarded {
		a.raise(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUser{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return
	}

	if !a.isPasswordValid(c.Password) {
		a.raise(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUserPassword{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return
	}

	authorizationCode := a.tokenGenerator.New()

	expiresAt := a.clock.Now().Add(authorizationCodeLifetime).Unix()

	a.raise(AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant{
		UserID:            c.UserID,
		ClientID:          c.ClientID,
		AuthorizationCode: authorizationCode,
		ExpiresAt:         expiresAt,
		Scope:             c.Scope,
	})
}

func (a *resourceOwner) isPasswordValid(password string) bool {
	return VerifyPassword(a.PasswordHash, password)
}

func (a *resourceOwner) raise(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.PendingEvents = append(a.PendingEvents, events...)
}
