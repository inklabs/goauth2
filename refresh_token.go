package goauth2

import (
	"time"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"
)

const refreshTokenGrantLifetime = 1 * time.Hour

func RefreshTokenCommandTypes() []string {
	return []string{
		RequestAccessTokenViaRefreshTokenGrant{}.CommandType(),
		IssueRefreshTokenToUser{}.CommandType(),
		RevokeRefreshTokenFromUser{}.CommandType(),
	}
}

type refreshToken struct {
	tokenGenerator        TokenGenerator
	clock                 clock.Clock
	Token                 string
	Scope                 string
	PendingEvents         []rangedb.Event
	Username              string
	IsLoaded              bool
	HasBeenPreviouslyUsed bool
	HasBeenRevoked        bool
	UserID                string
	ClientID              string
}

func newRefreshToken(iter rangedb.RecordIterator, generator TokenGenerator, clock clock.Clock) *refreshToken {
	aggregate := &refreshToken{
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

func (a *refreshToken) apply(event rangedb.Event) {
	switch e := event.(type) {

	case *RefreshTokenWasIssuedToUser:
		a.IsLoaded = true
		a.UserID = e.UserID
		a.Scope = e.Scope

	case *RefreshTokenWasIssuedToUserViaRefreshTokenGrant:
		a.HasBeenPreviouslyUsed = true

	case *RefreshTokenWasRevokedFromUser:
		a.HasBeenRevoked = true

	}
}

func (a *refreshToken) Handle(command Command) {
	switch c := command.(type) {

	case RequestAccessTokenViaRefreshTokenGrant:
		a.RequestAccessTokenViaRefreshTokenGrant(c)

	case IssueRefreshTokenToUser:
		a.IssueRefreshTokenToUser(c)

	case RevokeRefreshTokenFromUser:
		a.RevokeRefreshTokenFromUser(c)

	}
}

func (a *refreshToken) GetPendingEvents() []rangedb.Event {
	return a.PendingEvents
}

func (a *refreshToken) raise(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.PendingEvents = append(a.PendingEvents, events...)
}

func (a *refreshToken) RequestAccessTokenViaRefreshTokenGrant(c RequestAccessTokenViaRefreshTokenGrant) {
	if !a.IsLoaded {
		a.raise(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidRefreshToken{
			RefreshToken: c.RefreshToken,
			ClientID:     c.ClientID,
		})
		return
	}

	if a.HasBeenPreviouslyUsed {
		a.raise(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToPreviouslyUsedRefreshToken{
			RefreshToken: c.RefreshToken,
		})
		return
	}

	if a.HasBeenRevoked {
		a.raise(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToRevokedRefreshToken{
			RefreshToken: c.RefreshToken,
			ClientID:     c.ClientID,
		})
		return
	}

	if c.Scope != "" && a.Scope != c.Scope {
		a.raise(RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidScope{
			RefreshToken:   c.RefreshToken,
			ClientID:       c.ClientID,
			Scope:          a.Scope,
			RequestedScope: c.Scope,
		})
		return
	}

	nextRefreshToken := a.tokenGenerator.New()
	expiresAt := a.clock.Now().Add(refreshTokenGrantLifetime).Unix()

	a.raise(
		AccessTokenWasIssuedToUserViaRefreshTokenGrant{
			RefreshToken: c.RefreshToken,
			UserID:       a.UserID,
			ClientID:     c.ClientID,
			Scope:        c.Scope,
			ExpiresAt:    expiresAt,
		},
		RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
			RefreshToken:     c.RefreshToken,
			UserID:           a.UserID,
			ClientID:         c.ClientID,
			NextRefreshToken: nextRefreshToken,
			Scope:            c.Scope,
		},
	)
}

func (a *refreshToken) IssueRefreshTokenToUser(c IssueRefreshTokenToUser) {
	a.raise(RefreshTokenWasIssuedToUser{
		RefreshToken: c.RefreshToken,
		UserID:       c.UserID,
		ClientID:     c.ClientID,
		Scope:        c.Scope,
	})
}

func (a *refreshToken) RevokeRefreshTokenFromUser(c RevokeRefreshTokenFromUser) {
	a.raise(RefreshTokenWasRevokedFromUser{
		RefreshToken: c.RefreshToken,
		ClientID:     c.ClientID,
		UserID:       c.UserID,
	})
}
