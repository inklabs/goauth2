package goauth2

import (
	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"
)

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

func newAuthorizationCode(records <-chan *rangedb.Record, generator TokenGenerator, clock clock.Clock) *authorizationCode {
	aggregate := &authorizationCode{
		tokenGenerator: generator,
		clock:          clock,
	}

	for record := range records {
		if event, ok := record.Data.(rangedb.Event); ok {
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
		if !a.IsLoaded {
			a.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidAuthorizationCode{
				AuthorizationCode: c.AuthorizationCode,
				ClientID:          c.ClientID,
			})
			return
		}

		if a.ClientID != c.ClientID {
			a.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToUnmatchedClientApplicationID{
				AuthorizationCode: c.AuthorizationCode,
				RequestedClientID: c.ClientID,
				ActualClientID:    a.ClientID,
			})
			return
		}

		if a.HasBeenPreviouslyUsed {
			a.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode{
				AuthorizationCode: c.AuthorizationCode,
				ClientID:          c.ClientID,
				UserID:            a.UserID,
			})
			return
		}

		if a.isExpired() {
			a.emit(RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToExpiredAuthorizationCode{
				AuthorizationCode: c.AuthorizationCode,
				ClientID:          c.ClientID,
			})
			return
		}

		refreshToken := a.tokenGenerator.New()

		a.emit(
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

	case IssueAuthorizationCodeToUser:
		a.emit(AuthorizationCodeWasIssuedToUser{
			AuthorizationCode: c.AuthorizationCode,
			UserID:            c.UserID,
			ClientID:          c.ClientID,
			ExpiresAt:         c.ExpiresAt,
			Scope:             c.Scope,
		})

	}
}

func (a *authorizationCode) emit(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.PendingEvents = append(a.PendingEvents, events...)
}

func (a *authorizationCode) GetPendingEvents() []rangedb.Event {
	return a.PendingEvents
}

func (a *authorizationCode) isExpired() bool {
	return a.clock.Now().Unix() > a.ExpiresAt
}
