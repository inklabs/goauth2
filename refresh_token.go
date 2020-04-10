package goauth2

import (
	"github.com/inklabs/rangedb"
)

type refreshToken struct {
	tokenGenerator         TokenGenerator
	Token                  string
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
		a.Username = e.Username

	case *RefreshTokenWasIssuedToClientApplication:
		a.IsLoaded = true
		a.IsForClientApplication = true
		a.ClientID = e.ClientID

	case *RefreshTokenWasIssuedToUserViaRefreshTokenGrant:
		a.HasBeenPreviouslyUsed = true

	case *RefreshTokenWasRevoked:
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
			})
			return
		}

		nextRefreshToken, err := a.tokenGenerator.New()
		if err != nil {
			// TODO: emit error
			return
		}

		if a.IsForUser {
			a.emit(
				AccessTokenWasIssuedToUserViaRefreshTokenGrant{
					RefreshToken: c.RefreshToken,
					UserID:       a.UserID,
				},
				RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
					RefreshToken:     c.RefreshToken,
					UserID:           a.UserID,
					NextRefreshToken: nextRefreshToken,
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
