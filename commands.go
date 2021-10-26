package goauth2

import (
	"github.com/inklabs/rangedb"
)

// Command is the interface for CQRS commands.
type Command interface {
	rangedb.AggregateMessage
	CommandType() string
}

type CommandHandler interface {
	PendingEvents
	Handle(command Command)
}

type PreCommandHandler interface {
	PendingEvents
	CommandTypes() []string
	Handle(command Command) (shouldContinue bool)
}

type CommandDispatcher func(command Command) []rangedb.Event
type CommandHandlerFactory func(command Command) CommandHandler
