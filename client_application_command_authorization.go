package goauth2

import (
	"context"

	"github.com/inklabs/rangedb"
)

type clientApplicationCommandAuthorization struct {
	store         rangedb.Store
	pendingEvents []rangedb.Event
}

func newClientApplicationCommandAuthorization(store rangedb.Store) *clientApplicationCommandAuthorization {
	return &clientApplicationCommandAuthorization{
		store: store,
	}
}

func (h *clientApplicationCommandAuthorization) GetPendingEvents() []rangedb.Event {
	return h.pendingEvents
}

func (h *clientApplicationCommandAuthorization) CommandTypes() []string {
	return []string{
		RequestAccessTokenViaImplicitGrant{}.CommandType(),
		RequestAccessTokenViaROPCGrant{}.CommandType(),
		RequestAccessTokenViaRefreshTokenGrant{}.CommandType(),
		RequestAuthorizationCodeViaAuthorizationCodeGrant{}.CommandType(),
		RequestAccessTokenViaAuthorizationCodeGrant{}.CommandType(),
	}
}

func (h *clientApplicationCommandAuthorization) Handle(command Command) bool {
	switch c := command.(type) {

	case RequestAccessTokenViaImplicitGrant:
		return h.RequestAccessTokenViaImplicitGrant(c)

	case RequestAccessTokenViaROPCGrant:
		return h.RequestAccessTokenViaROPCGrant(c)

	case RequestAccessTokenViaRefreshTokenGrant:
		return h.RequestAccessTokenViaRefreshTokenGrant(c)

	case RequestAuthorizationCodeViaAuthorizationCodeGrant:
		return h.RequestAuthorizationCodeViaAuthorizationCodeGrant(c)

	case RequestAccessTokenViaAuthorizationCodeGrant:
		return h.RequestAccessTokenViaAuthorizationCodeGrant(c)

	}

	return true
}

func (h *clientApplicationCommandAuthorization) RequestAccessTokenViaImplicitGrant(c RequestAccessTokenViaImplicitGrant) bool {
	clientApplication := h.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		h.emit(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationID{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	if clientApplication.RedirectURI != c.RedirectURI {
		h.emit(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			UserID:      c.UserID,
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
		})
		return false
	}

	return true
}

func (h *clientApplicationCommandAuthorization) RequestAccessTokenViaROPCGrant(c RequestAccessTokenViaROPCGrant) bool {
	clientApplication := h.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		h.emit(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	if clientApplication.ClientSecret != c.ClientSecret {
		h.emit(RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	return true
}

func (h *clientApplicationCommandAuthorization) RequestAccessTokenViaRefreshTokenGrant(c RequestAccessTokenViaRefreshTokenGrant) bool {
	clientApplication := h.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		h.emit(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidClientApplicationCredentials{
			RefreshToken: c.RefreshToken,
			ClientID:     c.ClientID,
		})
		return false
	}

	if clientApplication.ClientSecret != c.ClientSecret {
		h.emit(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidClientApplicationCredentials{
			RefreshToken: c.RefreshToken,
			ClientID:     c.ClientID,
		})
		return false
	}

	return true
}

func (h *clientApplicationCommandAuthorization) RequestAuthorizationCodeViaAuthorizationCodeGrant(c RequestAuthorizationCodeViaAuthorizationCodeGrant) bool {
	clientApplication := h.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		h.emit(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{
			UserID:   c.UserID,
			ClientID: c.ClientID,
		})
		return false
	}

	if clientApplication.RedirectURI != c.RedirectURI {
		h.emit(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			UserID:      c.UserID,
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
		})
		return false
	}

	return true
}

func (h *clientApplicationCommandAuthorization) RequestAccessTokenViaAuthorizationCodeGrant(c RequestAccessTokenViaAuthorizationCodeGrant) bool {
	clientApplication := h.loadClientApplicationAggregate(c.ClientID)

	if !clientApplication.IsOnBoarded {
		h.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
		})
		return false
	}

	if clientApplication.ClientSecret != c.ClientSecret {
		h.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationSecret{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
		})
		return false
	}

	if clientApplication.RedirectURI != c.RedirectURI {
		h.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
			RedirectURI:       c.RedirectURI,
		})
		return false
	}

	return true
}

func (h *clientApplicationCommandAuthorization) loadClientApplicationAggregate(clientID string) *clientApplication {
	ctx := context.Background()
	return newClientApplication(h.store.EventsByStreamStartingWith(ctx, 0, clientApplicationStream(clientID)))
}

func (h *clientApplicationCommandAuthorization) emit(events ...rangedb.Event) {
	h.pendingEvents = append(h.pendingEvents, events...)
}
