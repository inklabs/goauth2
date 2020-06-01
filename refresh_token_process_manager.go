package goauth2

import (
	"github.com/inklabs/rangedb"
)

type refreshTokenProcessManager struct {
	dispatch                       CommandDispatcher
	authorizationCodeRefreshtokens *AuthorizationCodeRefreshTokens
}

func newRefreshTokenProcessManager(
	commandDispatcher CommandDispatcher,
	authorizationCodeRefreshTokens *AuthorizationCodeRefreshTokens,
) *refreshTokenProcessManager {
	return &refreshTokenProcessManager{
		dispatch:                       commandDispatcher,
		authorizationCodeRefreshtokens: authorizationCodeRefreshTokens,
	}
}

func (r *refreshTokenProcessManager) Accept(record *rangedb.Record) {
	switch event := record.Data.(type) {

	case *RefreshTokenWasIssuedToUserViaROPCGrant:
		r.dispatch(IssueRefreshTokenToUser{
			RefreshToken: event.RefreshToken,
			UserID:       event.UserID,
			ClientID:     event.ClientID,
			Scope:        event.Scope,
		})

	case *RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant:
		r.dispatch(IssueRefreshTokenToUser{
			RefreshToken: event.RefreshToken,
			UserID:       event.UserID,
			ClientID:     event.ClientID,
			Scope:        event.Scope,
		})

	case *RefreshTokenWasIssuedToUserViaRefreshTokenGrant:
		r.dispatch(IssueRefreshTokenToUser{
			RefreshToken: event.NextRefreshToken,
			UserID:       event.UserID,
			ClientID:     event.ClientID,
			Scope:        event.Scope,
		})

	case *RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode:
		for _, refreshToken := range r.authorizationCodeRefreshtokens.GetTokens(event.AuthorizationCode) {
			r.dispatch(RevokeRefreshTokenFromUser{
				RefreshToken: refreshToken,
				UserID:       event.UserID,
				ClientID:     event.ClientID,
			})
		}

	}
}
