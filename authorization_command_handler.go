package goauth2

import (
	"github.com/inklabs/rangedb"
)

type authorizationCommandHandler struct {
	store          rangedb.Store
	pendingEvents  []rangedb.Event
	tokenGenerator TokenGenerator
}

func newAuthorizationCommandHandler(store rangedb.Store, tokenGenerator TokenGenerator) *authorizationCommandHandler {
	return &authorizationCommandHandler{
		store:          store,
		tokenGenerator: tokenGenerator,
	}
}

func (h *authorizationCommandHandler) Handle(command Command) bool {
	switch c := command.(type) {

	case GrantUserAdministratorRole:
		grantingUser := h.loadResourceOwnerAggregate(c.GrantingUserID)

		if !grantingUser.IsOnBoarded {
			h.emit(GrantUserAdministratorRoleWasRejectedDueToMissingGrantingUser{
				UserID:         c.UserID,
				GrantingUserID: c.GrantingUserID,
			})
			return false
		}

		if !grantingUser.IsAdministrator {
			h.emit(GrantUserAdministratorRoleWasRejectedDueToNonAdministrator{
				UserID:         c.UserID,
				GrantingUserID: c.GrantingUserID,
			})
			return false
		}

	case AuthorizeUserToOnBoardClientApplications:
		authorizingUser := h.loadResourceOwnerAggregate(c.AuthorizingUserID)

		if !authorizingUser.IsOnBoarded {
			h.emit(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingAuthorizingUser{
				UserID:            c.UserID,
				AuthorizingUserID: c.AuthorizingUserID,
			})
			return false
		}

		if !authorizingUser.IsAdministrator {
			h.emit(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToNonAdministrator{
				UserID:            c.UserID,
				AuthorizingUserID: c.AuthorizingUserID,
			})
			return false
		}

	case OnBoardClientApplication:
		resourceOwner := h.loadResourceOwnerAggregate(c.UserID)

		if !resourceOwner.IsOnBoarded {
			h.emit(OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
				ClientID: c.ClientID,
				UserID:   c.UserID,
			})
			return false
		}

		if !resourceOwner.IsAuthorizedToOnboardClientApplications {
			h.emit(OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
				ClientID: c.ClientID,
				UserID:   c.UserID,
			})
			return false
		}

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

	}

	return true
}

func (h *authorizationCommandHandler) emit(events ...rangedb.Event) {
	h.pendingEvents = append(h.pendingEvents, events...)
}

func (h *authorizationCommandHandler) loadResourceOwnerAggregate(userID string) *resourceOwner {
	return newResourceOwner(h.store.AllEventsByStream(resourceOwnerStream(userID)), h.tokenGenerator)
}

func (h *authorizationCommandHandler) loadClientApplicationAggregate(clientID string) *clientApplication {
	return newClientApplication(h.store.AllEventsByStream(clientApplicationStream(clientID)))
}

func (h *authorizationCommandHandler) GetPendingEvents() []rangedb.Event {
	return h.pendingEvents
}
