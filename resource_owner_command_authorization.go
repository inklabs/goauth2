package goauth2

import (
	"context"

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

func (a *resourceOwnerCommandAuthorization) GetPendingEvents() []rangedb.Event {
	return a.pendingEvents
}

func (a *resourceOwnerCommandAuthorization) CommandTypes() []string {
	return []string{
		GrantUserAdministratorRole{}.CommandType(),
		AuthorizeUserToOnBoardClientApplications{}.CommandType(),
		OnBoardClientApplication{}.CommandType(),
	}
}

func (a *resourceOwnerCommandAuthorization) Handle(command Command) bool {
	switch c := command.(type) {

	case GrantUserAdministratorRole:
		return a.GrantUserAdministratorRole(c)

	case AuthorizeUserToOnBoardClientApplications:
		return a.AuthorizeUserToOnBoardClientApplications(c)

	case OnBoardClientApplication:
		return a.OnBoardClientApplication(c)

	}

	return true
}

func (a *resourceOwnerCommandAuthorization) GrantUserAdministratorRole(c GrantUserAdministratorRole) bool {
	grantingUser := a.loadResourceOwnerAggregate(c.GrantingUserID)

	if !grantingUser.IsOnBoarded {
		a.raise(GrantUserAdministratorRoleWasRejectedDueToMissingGrantingUser{
			UserID:         c.UserID,
			GrantingUserID: c.GrantingUserID,
		})
		return false
	}

	if !grantingUser.IsAdministrator {
		a.raise(GrantUserAdministratorRoleWasRejectedDueToNonAdministrator{
			UserID:         c.UserID,
			GrantingUserID: c.GrantingUserID,
		})
		return false
	}

	return true
}

func (a *resourceOwnerCommandAuthorization) AuthorizeUserToOnBoardClientApplications(c AuthorizeUserToOnBoardClientApplications) bool {
	authorizingUser := a.loadResourceOwnerAggregate(c.AuthorizingUserID)

	if !authorizingUser.IsOnBoarded {
		a.raise(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingAuthorizingUser{
			UserID:            c.UserID,
			AuthorizingUserID: c.AuthorizingUserID,
		})
		return false
	}

	if !authorizingUser.IsAdministrator {
		a.raise(AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToNonAdministrator{
			UserID:            c.UserID,
			AuthorizingUserID: c.AuthorizingUserID,
		})
		return false
	}

	return true
}

func (a *resourceOwnerCommandAuthorization) OnBoardClientApplication(c OnBoardClientApplication) bool {
	resourceOwner := a.loadResourceOwnerAggregate(c.UserID)

	if !resourceOwner.IsOnBoarded {
		a.raise(OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
			ClientID: c.ClientID,
			UserID:   c.UserID,
		})
		return false
	}

	if !resourceOwner.IsAuthorizedToOnboardClientApplications {
		a.raise(OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
			ClientID: c.ClientID,
			UserID:   c.UserID,
		})
		return false
	}

	return true
}

func (a *resourceOwnerCommandAuthorization) raise(events ...rangedb.Event) {
	a.pendingEvents = append(a.pendingEvents, events...)
}

func (a *resourceOwnerCommandAuthorization) loadResourceOwnerAggregate(userID string) *resourceOwner {
	return newResourceOwner(
		a.store.EventsByStream(context.Background(), 0, resourceOwnerStream(userID)),
		a.tokenGenerator,
		a.clock,
	)
}
