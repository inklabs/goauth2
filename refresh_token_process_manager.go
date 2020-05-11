package goauth2

import (
	"github.com/inklabs/rangedb"
)

type refreshTokenProcessManager struct {
	commandDispatcher              CommandDispatcher
	authorizationCodeRefreshtokens *AuthorizationCodeRefreshTokens
}

func newRefreshTokenProcessManager(
	commandDispatcher CommandDispatcher,
	authorizationCodeRefreshTokens *AuthorizationCodeRefreshTokens,
) *refreshTokenProcessManager {
	return &refreshTokenProcessManager{
		commandDispatcher:              commandDispatcher,
		authorizationCodeRefreshtokens: authorizationCodeRefreshTokens,
	}
}

func (r *refreshTokenProcessManager) Accept(record *rangedb.Record) {
	switch event := record.Data.(type) {

	case *RefreshTokenWasIssuedToUserViaROPCGrant:
		r.commandDispatcher(IssueRefreshTokenToUser{
			RefreshToken: event.RefreshToken,
			UserID:       event.UserID,
			ClientID:     event.ClientID,
			Scope:        event.Scope,
		})

	case *RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant:
		r.commandDispatcher(IssueRefreshTokenToUser{
			RefreshToken: event.RefreshToken,
			UserID:       event.UserID,
			ClientID:     event.ClientID,
			Scope:        event.Scope,
		})

	case *RefreshTokenWasIssuedToUserViaRefreshTokenGrant:
		r.commandDispatcher(IssueRefreshTokenToUser{
			RefreshToken: event.NextRefreshToken,
			UserID:       event.UserID,
			ClientID:     event.ClientID,
			Scope:        event.Scope,
		})

	case *RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode:
		for _, refreshToken := range r.authorizationCodeRefreshtokens.GetTokens(event.AuthorizationCode) {
			r.commandDispatcher(RevokeRefreshTokenFromUser{
				RefreshToken: refreshToken,
				UserID:       event.UserID,
				ClientID:     event.ClientID,
			})
		}

	}
}
