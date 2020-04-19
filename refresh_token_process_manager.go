package goauth2

import (
	"github.com/inklabs/rangedb"
)

type refreshTokenProcessManager struct {
	commandDispatcher CommandDispatcher
}

func newRefreshTokenProcessManager(commandDispatcher CommandDispatcher) *refreshTokenProcessManager {
	return &refreshTokenProcessManager{
		commandDispatcher: commandDispatcher,
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
	case *RefreshTokenWasIssuedToUserViaRefreshTokenGrant:
		r.commandDispatcher(IssueRefreshTokenToUser{
			RefreshToken: event.NextRefreshToken,
			UserID:       event.UserID,
			ClientID:     event.ClientID,
			Scope:        event.Scope,
		})
	}
}
