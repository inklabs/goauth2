package goauth2

import (
	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/provider/inmemorystore"
)

//App is the OAuth2 CQRS application.
type App struct {
	store rangedb.Store
}

// Option defines functional option parameters for App.
type Option func(*App)

//WithStore is a functional option to inject a RangeDB Event Store.
func WithStore(store rangedb.Store) Option {
	return func(app *App) {
		app.store = store
	}
}

//New constructs an OAuth2 CQRS application.
func New(options ...Option) *App {
	app := &App{
		store: inmemorystore.New(),
	}

	for _, option := range options {
		option(app)
	}

	return app
}

func (a *App) Dispatch(command Command) []rangedb.Event {
	var events []rangedb.Event

	switch command.(type) {
	case RequestAccessTokenViaClientCredentialsGrant:
		events = a.handleWithClientApplicationAggregate(command)

	}

	return events
}

func (a *App) handleWithClientApplicationAggregate(command Command) []rangedb.Event {
	aggregate := newClientApplication(a.store.AllEventsByStream(rangedb.GetEventStream(command)))
	aggregate.Handle(command)
	return a.savePendingEvents(aggregate)
}

func (a *App) savePendingEvents(events PendingEvents) []rangedb.Event {
	pendingEvents := events.GetPendingEvents()
	for _, event := range pendingEvents {
		_ = a.store.Save(event, nil)
	}
	return pendingEvents
}
