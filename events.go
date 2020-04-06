package goauth2

import (
	"github.com/inklabs/rangedb"
)

//go:generate go run github.com/inklabs/rangedb/gen/eventbinder -package goauth2 -files client_application_events.go

//SavedEvents contains events that have been persisted to the event store.
type SavedEvents []rangedb.Event

func (l *SavedEvents) Contains(events ...rangedb.Event) bool {
	var totalFound int
	for _, event := range events {
		for _, savedEvent := range *l {
			if event.EventType() == savedEvent.EventType() {
				totalFound++
				break
			}
		}
	}
	return len(events) == totalFound
}

//PendingEvents is the interface for retrieving CQRS events that will be saved to the event store.
type PendingEvents interface {
	GetPendingEvents() []rangedb.Event
}
