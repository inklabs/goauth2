package goauth2

import (
	"github.com/inklabs/rangedb"
)

type authorizationCommandHandler struct {
	store         rangedb.Store
	pendingEvents []rangedb.Event
}

func newAuthorizationCommandHandler(store rangedb.Store) *authorizationCommandHandler {
	return &authorizationCommandHandler{
		store: store,
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

	}

	return true
}

func (h *authorizationCommandHandler) emit(events ...rangedb.Event) {
	h.pendingEvents = append(h.pendingEvents, events...)
}

func (h *authorizationCommandHandler) loadResourceOwnerAggregate(userID string) *resourceOwner {
	return newResourceOwner(h.store.AllEventsByStream(resourceOwnerStream(userID)))
}

func (h *authorizationCommandHandler) GetPendingEvents() []rangedb.Event {
	return h.pendingEvents
}
