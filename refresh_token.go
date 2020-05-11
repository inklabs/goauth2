package goauth2

import (
	"github.com/inklabs/rangedb"
)

type refreshToken struct {
	tokenGenerator         TokenGenerator
	Token                  string
	Scope                  string
	PendingEvents          []rangedb.Event
	Username               string
	IsLoaded               bool
	HasBeenPreviouslyUsed  bool
	HasBeenRevoked         bool
	IsForUser              bool
	UserID                 string
	IsForClientApplication bool
	ClientID               string
}

func newRefreshToken(records <-chan *rangedb.Record, generator TokenGenerator) *refreshToken {
	aggregate := &refreshToken{
		tokenGenerator: generator,
	}

	for record := range records {
		if event, ok := record.Data.(rangedb.Event); ok {
			aggregate.apply(event)
		}
	}

	return aggregate
}

func (a *refreshToken) apply(event rangedb.Event) {
	switch e := event.(type) {

	case *RefreshTokenWasIssuedToUser:
		a.IsLoaded = true
		a.IsForUser = true
		a.UserID = e.UserID
		a.Scope = e.Scope

	case *RefreshTokenWasIssuedToClientApplication:
		a.IsLoaded = true
		a.IsForClientApplication = true
		a.ClientID = e.ClientID

	case *RefreshTokenWasIssuedToUserViaRefreshTokenGrant:
		a.HasBeenPreviouslyUsed = true

	case *RefreshTokenWasRevokedFromUser:
		a.HasBeenRevoked = true

	}
}

func (a *refreshToken) Handle(command Command) {
	switch c := command.(type) {

	case RequestAccessTokenViaRefreshTokenGrant:
		if !a.IsLoaded {
			a.emit(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidRefreshToken{
				RefreshToken: c.RefreshToken,
				ClientID:     c.ClientID,
			})
			return
		}

		if a.HasBeenPreviouslyUsed {
			a.emit(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToPreviouslyUsedRefreshToken{
				RefreshToken: c.RefreshToken,
			})
			return
		}

		if a.HasBeenRevoked {
			a.emit(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToRevokedRefreshToken{
				RefreshToken: c.RefreshToken,
				ClientID:     c.ClientID,
			})
			return
		}

		if c.Scope != "" && a.Scope != c.Scope {
			a.emit(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidScope{
				RefreshToken:   c.RefreshToken,
				ClientID:       c.ClientID,
				Scope:          a.Scope,
				RequestedScope: c.Scope,
			})
			return
		}

		nextRefreshToken := a.tokenGenerator.New()

		if a.IsForUser {
			a.emit(
				AccessTokenWasIssuedToUserViaRefreshTokenGrant{
					RefreshToken: c.RefreshToken,
					UserID:       a.UserID,
					ClientID:     c.ClientID,
				},
				RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
					RefreshToken:     c.RefreshToken,
					UserID:           a.UserID,
					ClientID:         c.ClientID,
					NextRefreshToken: nextRefreshToken,
					Scope:            a.Scope,
				},
			)
		} else if a.IsForClientApplication {
			a.emit(
				AccessTokenWasIssuedToClientApplicationViaRefreshTokenGrant{
					RefreshToken: c.RefreshToken,
					ClientID:     c.ClientID,
				},
				RefreshTokenWasIssuedToClientApplicationViaRefreshTokenGrant{
					RefreshToken:     c.RefreshToken,
					ClientID:         a.ClientID,
					NextRefreshToken: nextRefreshToken,
				},
			)
		}

	case IssueRefreshTokenToUser:
		a.emit(RefreshTokenWasIssuedToUser{
			RefreshToken: c.RefreshToken,
			UserID:       c.UserID,
			ClientID:     c.ClientID,
			Scope:        c.Scope,
		})

	case RevokeRefreshTokenFromUser:
		a.emit(RefreshTokenWasRevokedFromUser{
			RefreshToken: c.RefreshToken,
			ClientID:     c.ClientID,
			UserID:       c.UserID,
		})

	}
}

func (a *refreshToken) emit(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.PendingEvents = append(a.PendingEvents, events...)
}

func (a *refreshToken) GetPendingEvents() []rangedb.Event {
	return a.PendingEvents
}
