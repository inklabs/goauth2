package bdd

import (
	"reflect"
	"testing"

	"github.com/inklabs/rangedb"
	"github.com/stretchr/testify/assert"
)

type Command interface {
	rangedb.AggregateMessage
	CommandType() string
}

type CommandDispatcher func(command Command)

type TestCase struct {
	store          rangedb.Store
	dispatch       CommandDispatcher
	previousEvents []rangedb.Event
	command        Command
}

func New(store rangedb.Store, commandDispatcher CommandDispatcher) *TestCase {
	return &TestCase{
		store:    store,
		dispatch: commandDispatcher,
	}
}

func (c *TestCase) Given(events ...rangedb.Event) *TestCase {
	c.previousEvents = events
	return c
}

func (c *TestCase) When(command Command) *TestCase {
	c.command = command
	return c
}

func (c *TestCase) Then(expectedEvents ...rangedb.Event) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()

		streamPreviousEventCounts := make(map[string]uint64)
		for _, event := range c.previousEvents {
			streamPreviousEventCounts[rangedb.GetEventStream(event)]++
			_ = c.store.Save(event, nil)
		}

		c.dispatch(c.command)

		streamExpectedEvents := make(map[string][]rangedb.Event)
		for _, event := range expectedEvents {
			stream := rangedb.GetEventStream(event)

			streamExpectedEvents[stream] = append(streamExpectedEvents[stream], event)
		}

		for stream, expectedEventsInStream := range streamExpectedEvents {
			eventNumber := streamPreviousEventCounts[stream]
			actualEvents := eventChannelToSlice(c.store.EventsByStreamStartingWith(stream, eventNumber))

			assert.Equal(t, expectedEventsInStream, actualEvents, "stream: %s", stream)
		}
	}
}

func (c *TestCase) ThenInspectEvents(f func(t *testing.T, events []rangedb.Event)) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		streamPreviousEventCounts := make(map[string]uint64)
		for _, event := range c.previousEvents {
			streamPreviousEventCounts[rangedb.GetEventStream(event)]++
			_ = c.store.Save(event, nil)
		}

		c.dispatch(c.command)

		var events []rangedb.Event
		for _, stream := range getStreamsFromStore(c.store) {
			eventNumber := streamPreviousEventCounts[stream]
			actualEvents := eventChannelToSlice(c.store.EventsByStreamStartingWith(stream, eventNumber))

			events = append(events, actualEvents...)
		}

		f(t, events)
	}
}

func getStreamsFromStore(store rangedb.Store) []string {
	streams := make(map[string]struct{})
	for record := range store.AllEvents() {
		streams[rangedb.GetStream(record.AggregateType, record.AggregateID)] = struct{}{}
	}

	keys := make([]string, 0, len(streams))
	for k := range streams {
		keys = append(keys, k)
	}
	return keys
}

func eventChannelToSlice(records <-chan *rangedb.Record) []rangedb.Event {
	var events []rangedb.Event

	for record := range records {
		events = append(events, eventAsValue(record.Data))
	}

	return events
}

func eventAsValue(inputEvent interface{}) rangedb.Event {
	var event rangedb.Event
	reflectedValue := reflect.ValueOf(inputEvent)

	if reflectedValue.Kind() == reflect.Ptr {
		event = reflectedValue.Elem().Interface().(rangedb.Event)
	} else {
		event = inputEvent.(rangedb.Event)
	}
	return event
}
