package goauth2

import (
	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"
)

type resourceOwnerCommandAuthorization struct {
	store          rangedb.Store
	clock          clock.Clock
	tokenGenerator TokenGenerator
	pendingEvents  []rangedb.Event
}

func newResourceOwnerCommandAuthorization(
	store rangedb.Store,
	tokenGenerator TokenGenerator,
	clock clock.Clock,
) *resourceOwnerCommandAuthorization {
	return &resourceOwnerCommandAuthorization{
		store:          store,
		tokenGenerator: tokenGenerator,
		clock:          clock,
	}
}

func (a *resourceOwnerCommandAuthorization) Handle(command Command) bool {
	switch c := command.(type) {

	case GrantUserAdministratorRole:
		grantingUser := a.loadResourceOwnerAggregate(c.GrantingUserID)

		if !grantingUser.IsOnBoarded {
			a.emit(GrantUserAdministratorRoleWasRejectedDueToMissingGrantingUser{
				UserID:         c.UserID,
				GrantingUserID: c.GrantingUserID,
			})
			return false
		}

		if !grantingUser.IsAdministrator {
			a.emit(GrantUserAdministratorRoleWasRejectedDueToNonAdministrator{
				UserID:         c.UserID,
				GrantingUserID: c.GrantingUserID,
			})
			return false
		}

	case AuthorizeUserToOnBoardClientApplications:
		authorizingUser := a.loadResourceOwnerAggregate(c.AuthorizingUserID)

		if !authorizingUser.IsOnBoarded {
			a.emit(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingAuthorizingUser{
				UserID:            c.UserID,
				AuthorizingUserID: c.AuthorizingUserID,
			})
			return false
		}

		if !authorizingUser.IsAdministrator {
			a.emit(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToNonAdministrator{
				UserID:            c.UserID,
				AuthorizingUserID: c.AuthorizingUserID,
			})
			return false
		}

	case OnBoardClientApplication:
		resourceOwner := a.loadResourceOwnerAggregate(c.UserID)

		if !resourceOwner.IsOnBoarded {
			a.emit(OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
				ClientID: c.ClientID,
				UserID:   c.UserID,
			})
			return false
		}

		if !resourceOwner.IsAuthorizedToOnboardClientApplications {
			a.emit(OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
				ClientID: c.ClientID,
				UserID:   c.UserID,
			})
			return false
		}

	}

	return true
}

func (a *resourceOwnerCommandAuthorization) emit(events ...rangedb.Event) {
	a.pendingEvents = append(a.pendingEvents, events...)
}

func (a *resourceOwnerCommandAuthorization) loadResourceOwnerAggregate(userID string) *resourceOwner {
	return newResourceOwner(a.store.AllEventsByStream(resourceOwnerStream(userID)), a.tokenGenerator, a.clock)
}

func (a *resourceOwnerCommandAuthorization) GetPendingEvents() []rangedb.Event {
	return a.pendingEvents
}
