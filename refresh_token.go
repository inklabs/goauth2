package goauth2

import (
	"github.com/inklabs/rangedb"
)

func RefreshTokenCommandTypes() []string {
	return []string{
		RequestAccessTokenViaRefreshTokenGrant{}.CommandType(),
		IssueRefreshTokenToUser{}.CommandType(),
		RevokeRefreshTokenFromUser{}.CommandType(),
	}
}

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

func newRefreshToken(iter rangedb.RecordIterator, generator TokenGenerator) *refreshToken {
	aggregate := &refreshToken{
		tokenGenerator: generator,
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

	if a.IsForUser {
		a.raise(
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
		a.raise(
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
