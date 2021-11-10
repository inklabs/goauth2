package web

import (
	"reflect"

	"github.com/inklabs/rangedb"
)

// SavedEvents contains events that have been persisted to the event store.
type SavedEvents []rangedb.Event

// Contains returns true if all events are found.
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

// ContainsAny returns true if any events are found.
func (l *SavedEvents) ContainsAny(events ...rangedb.Event) bool {
	for _, event := range events {
		for _, savedEvent := range *l {
			if event.EventType() == savedEvent.EventType() {
				return true
			}
		}
	}

	return false
}

// Get returns true if the event was found and stores the result
// in the value pointed to by event. If it is not found, Get
// returns false.
func (l *SavedEvents) Get(event rangedb.Event) bool {
	for _, savedEvent := range *l {
		if event.EventType() == savedEvent.EventType() {
			eventVal := reflect.ValueOf(event)
			savedEventVal := reflect.ValueOf(savedEvent)

			if savedEventVal.Kind() == reflect.Ptr {
				savedEventVal = savedEventVal.Elem()
			}

			if savedEventVal.Type().AssignableTo(eventVal.Type().Elem()) {
				eventVal.Elem().Set(savedEventVal)
				return true
			}
		}
	}

	return false
}
