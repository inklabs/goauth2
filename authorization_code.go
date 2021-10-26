package goauth2

import (
	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"
)

func AuthorizationCodeCommandTypes() []string {
	return []string{
		RequestAccessTokenViaAuthorizationCodeGrant{}.CommandType(),
		IssueAuthorizationCodeToUser{}.CommandType(),
	}
}

type authorizationCode struct {
	tokenGenerator        TokenGenerator
	clock                 clock.Clock
	IsLoaded              bool
	ExpiresAt             int64
	UserID                string
	ClientID              string
	Scope                 string
	HasBeenPreviouslyUsed bool
	PendingEvents         []rangedb.Event
}

func newAuthorizationCode(iter rangedb.RecordIterator, generator TokenGenerator, clock clock.Clock) *authorizationCode {
	aggregate := &authorizationCode{
		tokenGenerator: generator,
		clock:          clock,
	}

	for iter.Next() {
		if event, ok := iter.Record().Data.(rangedb.Event); ok {
			aggregate.apply(event)
		}
	}

	return aggregate
}

func (a *authorizationCode) apply(event rangedb.Event) {
	switch e := event.(type) {

	case *AuthorizationCodeWasIssuedToUser:
		a.IsLoaded = true
		a.ExpiresAt = e.ExpiresAt
		a.UserID = e.UserID
		a.ClientID = e.ClientID
		a.Scope = e.Scope

	case *AccessTokenWasIssuedToUserViaAuthorizationCodeGrant:
		a.HasBeenPreviouslyUsed = true

	case *RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant:
		a.HasBeenPreviouslyUsed = true

	}
}

func (a *authorizationCode) Handle(command Command) {
	switch c := command.(type) {

	case RequestAccessTokenViaAuthorizationCodeGrant:
		a.RequestAccessTokenViaAuthorizationCodeGrant(c)

	case IssueAuthorizationCodeToUser:
		a.IssueAuthorizationCodeToUser(c)

	}
}

func (a *authorizationCode) RequestAccessTokenViaAuthorizationCodeGrant(c RequestAccessTokenViaAuthorizationCodeGrant) {
	if !a.IsLoaded {
		a.raise(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidAuthorizationCode{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
		})
		return
	}

	if a.ClientID != c.ClientID {
		a.raise(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToUnmatchedClientApplicationID{
			AuthorizationCode: c.AuthorizationCode,
			RequestedClientID: c.ClientID,
			ActualClientID:    a.ClientID,
		})
		return
	}

	if a.HasBeenPreviouslyUsed {
		a.raise(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
			UserID:            a.UserID,
		})
		return
	}

	if a.isExpired() {
		a.raise(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToExpiredAuthorizationCode{
			AuthorizationCode: c.AuthorizationCode,
			ClientID:          c.ClientID,
		})
		return
	}

	refreshToken := a.tokenGenerator.New()

	a.raise(
		AccessTokenWasIssuedToUserViaAuthorizationCodeGrant{
			AuthorizationCode: c.AuthorizationCode,
			UserID:            a.UserID,
			ClientID:          c.ClientID,
			Scope:             a.Scope,
		},
		RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
			AuthorizationCode: c.AuthorizationCode,
			UserID:            a.UserID,
			ClientID:          c.ClientID,
			RefreshToken:      refreshToken,
			Scope:             a.Scope,
		},
	)
}

func (a *authorizationCode) IssueAuthorizationCodeToUser(c IssueAuthorizationCodeToUser) {
	a.raise(AuthorizationCodeWasIssuedToUser{
		AuthorizationCode: c.AuthorizationCode,
		UserID:            c.UserID,
		ClientID:          c.ClientID,
		ExpiresAt:         c.ExpiresAt,
		Scope:             c.Scope,
	})
}

func (a *authorizationCode) GetPendingEvents() []rangedb.Event {
	return a.PendingEvents
}

func (a *authorizationCode) isExpired() bool {
	return a.clock.Now().Unix() > a.ExpiresAt
}

func (a *authorizationCode) raise(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.PendingEvents = append(a.PendingEvents, events...)
}
