package goauth2

import (
	"log"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"
	"github.com/inklabs/rangedb/provider/inmemorystore"

	"github.com/inklabs/goauth2/provider/uuidtoken"
)

//App is the OAuth2 CQRS application.
type App struct {
	clock              clock.Clock
	store              rangedb.Store
	tokenGenerator     TokenGenerator
	preCommandHandlers []PreCommandHandler
	logger             *log.Logger
}

// Option defines functional option parameters for App.
type Option func(*App)

//WithClock is a functional option to inject a clock.
func WithClock(clock clock.Clock) Option {
	return func(app *App) {
		app.clock = clock
	}
}

//WithStore is a functional option to inject a RangeDB Event Store.
func WithStore(store rangedb.Store) Option {
	return func(app *App) {
		app.store = store
	}
}

//WithTokenGenerator is a functional option to inject a token generator.
func WithTokenGenerator(generator TokenGenerator) Option {
	return func(app *App) {
		app.tokenGenerator = generator
	}
}

// WithLogger is a functional option to inject a Logger.
func WithLogger(logger *log.Logger) Option {
	return func(app *App) {
		app.logger = logger
	}
}

//New constructs an OAuth2 CQRS application.
func New(options ...Option) *App {
	app := &App{
		store:          inmemorystore.New(),
		tokenGenerator: uuidtoken.NewGenerator(),
	}

	for _, option := range options {
		option(app)
	}

	BindEvents(app.store)

	app.preCommandHandlers = []PreCommandHandler{
		newResourceOwnerCommandAuthorization(app.store, app.tokenGenerator, app.clock),
		newClientApplicationCommandAuthorization(app.store),
	}

	return app
}

func (a *App) Dispatch(command Command) []rangedb.Event {
	var events []rangedb.Event

	for _, handler := range a.preCommandHandlers {
		shouldContinue := handler.Handle(command)
		events = append(events, a.savePendingEvents(handler)...)

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

	case AuthorizeUserToOnBoardClientApplications:
		events = a.handleWithResourceOwnerAggregate(command)

	case OnBoardClientApplication:
		events = a.handleWithClientApplicationAggregate(command)

	case RequestAccessTokenViaImplicitGrant:
		events = a.handleWithResourceOwnerAggregate(command)

	case RequestAccessTokenViaROPCGrant:
		events = a.handleWithResourceOwnerAggregate(command)

	case RequestAccessTokenViaRefreshTokenGrant:
		events = a.handleWithRefreshTokenAggregate(command)

	case RequestAuthorizationCodeViaAuthorizationCodeGrant:
		events = a.handleWithResourceOwnerAggregate(command)

	case RequestAccessTokenViaAuthorizationCodeGrant:
		events = a.handleWithAuthorizationCodeAggregate(command)

	}

	return events
}

func (a *App) handleWithClientApplicationAggregate(command Command) []rangedb.Event {
	aggregate := newClientApplication(a.store.AllEventsByStream(rangedb.GetEventStream(command)))
	aggregate.Handle(command)
	return a.savePendingEvents(aggregate)
}

func (a *App) handleWithResourceOwnerAggregate(command Command) []rangedb.Event {
	aggregate := newResourceOwner(
		a.store.AllEventsByStream(rangedb.GetEventStream(command)),
		a.tokenGenerator,
		a.clock,
	)
	aggregate.Handle(command)
	return a.savePendingEvents(aggregate)
}

func (a *App) handleWithRefreshTokenAggregate(command Command) []rangedb.Event {
	aggregate := newRefreshToken(
		a.store.AllEventsByStream(rangedb.GetEventStream(command)),
		a.tokenGenerator,
	)
	aggregate.Handle(command)
	return a.savePendingEvents(aggregate)
}

func (a *App) handleWithAuthorizationCodeAggregate(command Command) []rangedb.Event {
	aggregate := newAuthorizationCode(
		a.store.AllEventsByStream(rangedb.GetEventStream(command)),
		a.tokenGenerator,
		a.clock,
	)
	aggregate.Handle(command)
	return a.savePendingEvents(aggregate)
}

func (a *App) savePendingEvents(events PendingEvents) []rangedb.Event {
	pendingEvents := events.GetPendingEvents()
	for _, event := range pendingEvents {
		err := a.store.Save(event, nil)
		if err != nil {
			a.logger.Printf("unable to save event: %v", err)
		}
	}
	return pendingEvents
}

func (a *App) SubscribeAndReplay(subscribers ...rangedb.RecordSubscriber) {
	a.store.SubscribeAndReplay(subscribers...)
}

func resourceOwnerStream(userID string) string {
	return rangedb.GetEventStream(UserWasOnBoarded{UserID: userID})
}

func clientApplicationStream(clientID string) string {
	return rangedb.GetEventStream(ClientApplicationWasOnBoarded{ClientID: clientID})
}
