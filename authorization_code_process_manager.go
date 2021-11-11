package goauth2

import (
	"github.com/inklabs/rangedb"
)

type authorizationCodeProcessManager struct {
	dispatch CommandDispatcher
}

func newAuthorizationCodeProcessManager(commandDispatcher CommandDispatcher) *authorizationCodeProcessManager {
	return &authorizationCodeProcessManager{
		dispatch: commandDispatcher,
	}
}

// Accept receives a rangedb.Record.
func (r *authorizationCodeProcessManager) Accept(record *rangedb.Record) {
	switch event := record.Data.(type) {
	case *AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant:
		r.dispatch(IssueAuthorizationCodeToUser{
			AuthorizationCode: event.AuthorizationCode,
			UserID:            event.UserID,
			ClientID:          event.ClientID,
			ExpiresAt:         event.ExpiresAt,
			Scope:             event.Scope,
		})
	}
}
