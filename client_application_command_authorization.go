package goauth2

import (
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

		if clientApplication.RedirectUri != c.RedirectUri {
			h.emit(RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationRedirectUri{
				UserID:      c.UserID,
				ClientID:    c.ClientID,
				RedirectUri: c.RedirectUri,
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

		if clientApplication.RedirectUri != c.RedirectUri {
			h.emit(RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectUri{
				UserID:      c.UserID,
				ClientID:    c.ClientID,
				RedirectUri: c.RedirectUri,
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

		if clientApplication.RedirectUri != c.RedirectUri {
			h.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectUri{
				AuthorizationCode: c.AuthorizationCode,
				ClientID:          c.ClientID,
				RedirectUri:       c.RedirectUri,
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
	return newClientApplication(h.store.AllEventsByStream(clientApplicationStream(clientID)))
}

func (h *clientApplicationCommandAuthorization) GetPendingEvents() []rangedb.Event {
	return h.pendingEvents
}
