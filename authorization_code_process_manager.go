package goauth2

import (
	"github.com/inklabs/rangedb"
)

type authorizationCodeProcessManager struct {
	commandDispatcher CommandDispatcher
}

func newAuthorizationCodeProcessManager(commandDispatcher CommandDispatcher) *authorizationCodeProcessManager {
	return &authorizationCodeProcessManager{
		commandDispatcher: commandDispatcher,
	}
}

func (r *authorizationCodeProcessManager) Accept(record *rangedb.Record) {
	switch event := record.Data.(type) {
	case *AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant:
		r.commandDispatcher(IssueAuthorizationCodeToUser{
			AuthorizationCode: event.AuthorizationCode,
			UserID:            event.UserID,
			ClientID:          event.ClientID,
			ExpiresAt:         event.ExpiresAt,
			Scope:             event.Scope,
		})
	}
}
