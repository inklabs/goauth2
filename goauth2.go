package goauth2

import (
	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/provider/inmemorystore"
)

//App is the OAuth2 CQRS application.
type App struct {
	store              rangedb.Store
	preCommandHandlers []PreCommandHandler
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

	app.preCommandHandlers = []PreCommandHandler{
		newAuthorizationCommandHandler(app.store),
	}

	return app
}

func (a *App) Dispatch(command Command) []rangedb.Event {
	var events []rangedb.Event

	for _, handler := range a.preCommandHandlers {
		shouldContinue := handler.Handle(command)
		a.savePendingEvents(handler)

		if !shouldContinue {
			return events
		}
	}

	switch command.(type) {
	case RequestAccessTokenViaClientCredentialsGrant:
		events = a.handleWithClientApplicationAggregate(command)

	case OnBoardUser:
		events = a.handleWithResourceOwnerAggregate(command)

	case GrantUserAdministratorRole:
		events = a.handleWithResourceOwnerAggregate(command)

	}

	return events
}

func (a *App) handleWithClientApplicationAggregate(command Command) []rangedb.Event {
	aggregate := newClientApplication(a.store.AllEventsByStream(rangedb.GetEventStream(command)))
	aggregate.Handle(command)
	return a.savePendingEvents(aggregate)
}

func (a *App) handleWithResourceOwnerAggregate(command Command) []rangedb.Event {
	aggregate := newResourceOwner(a.store.AllEventsByStream(rangedb.GetEventStream(command)))
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

func resourceOwnerStream(userID string) string {
	return rangedb.GetEventStream(UserWasOnBoarded{UserID: userID})
}
