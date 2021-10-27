package goauth2

import (
	"context"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"
)

type clientApplicationCommandAuthorization struct {
	store         rangedb.Store
	clock         clock.Clock
	pendingEvents []rangedb.Event
}

func newClientApplicationCommandAuthorization(
	store rangedb.Store,
	clock clock.Clock,
) *clientApplicationCommandAuthorization {
	return &clientApplicationCommandAuthorization{
		store: store,
		clock: clock,
	}
}

func (a *clientApplicationCommandAuthorization) GetPendingEvents() []rangedb.Event {
	return a.pendingEvents
}

func (a *clientApplicationCommandAuthorization) CommandTypes() []string {
	return []string{
		RequestAccessTokenViaImplicitGrant{}.CommandType(),
		RequestAccessTokenViaROPCGrant{}.CommandType(),
		RequestAccessTokenViaRefreshTokenGrant{}.CommandType(),
		RequestAuthorizationCodeViaAuthorizationCodeGrant{}.CommandType(),
		RequestAccessTokenViaAuthorizationCodeGrant{}.CommandType(),
	}
}

func (a *clientApplicationCommandAuthorization) Handle(command Command) bool {
	switch c := command.(type) {

	case RequestAccessTokenViaImplicitGrant:
		return a.RequestAccessTokenViaImplicitGrant(c)

	case RequestAccessTokenViaROPCGrant:
		return a.RequestAccessTokenViaROPCGrant(c)

	case RequestAccessTokenViaRefreshTokenGrant:
		return a.RequestAccessTokenViaRefreshTokenGrant(c)

	case RequestAuthorizationCodeViaAuthorizationCodeGrant:
		return a.RequestAuthorizationCodeViaAuthorizationCodeGrant(c)

	case RequestAccessTokenViaAuthorizationCodeGrant:
		return a.RequestAccessTokenViaAuthorizationCodeGrant(c)

	}

	return true
}

func (a *clientApplicationCommandAuthorization) RequestAccessTokenViaImplicitGrant(c RequestAccessTokenViaImplicitGrant) bool {
	clientApplication := a.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		a.raise(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationID{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	if clientApplication.RedirectURI != c.RedirectURI {
		a.raise(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			UserID:      c.UserID,
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
		})
		return false
	}

	return true
}

func (a *clientApplicationCommandAuthorization) RequestAccessTokenViaROPCGrant(c RequestAccessTokenViaROPCGrant) bool {
	clientApplication := a.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		a.raise(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	if clientApplication.ClientSecret != c.ClientSecret {
		a.raise(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	return true
}

func (a *clientApplicationCommandAuthorization) RequestAccessTokenViaRefreshTokenGrant(c RequestAccessTokenViaRefreshTokenGrant) bool {
	clientApplication := a.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		a.raise(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidClientApplicationCredentials{
			RefreshToken: c.RefreshToken,
			ClientID:     c.ClientID,
		})
		return false
	}

	if clientApplication.ClientSecret != c.ClientSecret {
		a.raise(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidClientApplicationCredentials{
			RefreshToken: c.RefreshToken,
			ClientID:     c.ClientID,
		})
		return false
	}

	return true
}

func (a *clientApplicationCommandAuthorization) RequestAuthorizationCodeViaAuthorizationCodeGrant(c RequestAuthorizationCodeViaAuthorizationCodeGrant) bool {
	clientApplication := a.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		a.raise(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	if clientApplication.RedirectURI != c.RedirectURI {
		a.raise(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			UserID:      c.UserID,
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
		})
		return false
	}

	return true
}

func (a *clientApplicationCommandAuthorization) RequestAccessTokenViaAuthorizationCodeGrant(c RequestAccessTokenViaAuthorizationCodeGrant) bool {
	clientApplication := a.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		a.raise(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
		})
		return false
	}

	if clientApplication.ClientSecret != c.ClientSecret {
		a.raise(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationSecret{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
		})
		return false
	}

	if clientApplication.RedirectURI != c.RedirectURI {
		a.raise(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
			RedirectURI:       c.RedirectURI,
		})
		return false
	}

	return true
}

func (a *clientApplicationCommandAuthorization) loadClientApplicationAggregate(clientID string) *clientApplication {
	ctx := context.Background()
	return newClientApplication(
		a.store.EventsByStream(ctx, 0, clientApplicationStream(clientID)),
		a.clock,
	)
}

func (a *clientApplicationCommandAuthorization) raise(events ...rangedb.Event) {
	a.pendingEvents = append(a.pendingEvents, events...)
}
