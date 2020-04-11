package goauth2

import (
	"github.com/inklabs/rangedb"
)

//go:generate go run github.com/inklabs/rangedb/gen/eventbinder -package goauth2 -files client_application_events.go,resource_owner_events.go,refresh_token_events.go,authorization_code_events.go

//PendingEvents is the interface for retrieving CQRS events that will be saved to the event store.
type PendingEvents interface {
	GetPendingEvents() []rangedb.Event
}
