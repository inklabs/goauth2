package goauth2

import (
	"github.com/inklabs/rangedb"
)

//Command is the interface for CQRS commands.
type Command interface {
	rangedb.AggregateMessage
	CommandType() string
}

type PreCommandHandler interface {
	PendingEvents
	Handle(command Command) (shouldContinue bool)
}
