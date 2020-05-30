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

func (h *clientApplicationCommandAuthorization) Handle(command Command) bool {
	switch c := command.(type) {

	case RequestAccessTokenViaImplicitGrant:
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

	case RequestAccessTokenViaROPCGrant:
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

	case RequestAccessTokenViaRefreshTokenGrant:
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

	case RequestAuthorizationCodeViaAuthorizationCodeGrant:
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

	case RequestAccessTokenViaAuthorizationCodeGrant:
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

	}

	return true
}

func (h *clientApplicationCommandAuthorization) emit(events ...rangedb.Event) {
	h.pendingEvents = append(h.pendingEvents, events...)
}

func (h *clientApplicationCommandAuthorization) loadClientApplicationAggregate(clientID string) *clientApplication {
	ctx := context.Background()
	return newClientApplication(h.store.EventsByStreamStartingWith(ctx, 0, clientApplicationStream(clientID)))
}

func (h *clientApplicationCommandAuthorization) GetPendingEvents() []rangedb.Event {
	return h.pendingEvents
}
