package goauth2

import (
	"context"
	"log"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock"
	"github.com/inklabs/rangedb/pkg/clock/provider/systemclock"
	"github.com/inklabs/rangedb/provider/inmemorystore"

	"github.com/inklabs/goauth2/provider/uuidtoken"
)

//App is the OAuth2 CQRS application.
type App struct {
	clock                   clock.Clock
	store                   rangedb.Store
	tokenGenerator          TokenGenerator
	preCommandHandlers      map[string][]PreCommandHandler
	commandHandlerFactories map[string]CommandHandlerFactory
	logger                  *log.Logger
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
		store:                   inmemorystore.New(),
		tokenGenerator:          uuidtoken.NewGenerator(),
		clock:                   systemclock.New(),
		commandHandlerFactories: make(map[string]CommandHandlerFactory),
		preCommandHandlers:      make(map[string][]PreCommandHandler),
	}

	for _, option := range options {
		option(app)
	}

	BindEvents(app.store)

	app.RegisterPreCommandHandler(newClientApplicationCommandAuthorization(app.store))
	app.RegisterPreCommandHandler(newResourceOwnerCommandAuthorization(app.store, app.tokenGenerator, app.clock))

	app.RegisterCommandHandler(ResourceOwnerCommandTypes(), app.newResourceOwnerAggregate)
	app.RegisterCommandHandler(ClientApplicationCommandTypes(), app.newClientApplicationAggregate)
	app.RegisterCommandHandler(AuthorizationCodeCommandTypes(), app.newAuthorizationCodeAggregate)
	app.RegisterCommandHandler(RefreshTokenCommandTypes(), app.newRefreshTokenAggregate)

	authorizationCodeRefreshTokens := NewAuthorizationCodeRefreshTokens()
	app.SubscribeAndReplay(authorizationCodeRefreshTokens)

	app.store.Subscribe(
		newRefreshTokenProcessManager(app.Dispatch, authorizationCodeRefreshTokens),
		newAuthorizationCodeProcessManager(app.Dispatch),
	)

	return app
}

func (a *App) RegisterPreCommandHandler(handler PreCommandHandler) {
	for _, commandType := range handler.CommandTypes() {
		a.preCommandHandlers[commandType] = append(a.preCommandHandlers[commandType], handler)
	}
}

func (a *App) RegisterCommandHandler(commandTypes []string, factory CommandHandlerFactory) {
	for _, commandType := range commandTypes {
		a.commandHandlerFactories[commandType] = factory
	}
}

func (a *App) Dispatch(command Command) []rangedb.Event {
	var preHandlerEvents []rangedb.Event

	preCommandHandlers, ok := a.preCommandHandlers[command.CommandType()]
	if ok {
		for _, handler := range preCommandHandlers {
			shouldContinue := handler.Handle(command)
			preHandlerEvents = append(preHandlerEvents, a.savePendingEvents(handler)...)

			if !shouldContinue {
				return preHandlerEvents
			}
		}
	}

	newCommandHandler, ok := a.commandHandlerFactories[command.CommandType()]
	if !ok {
		a.logger.Printf("command handler not found")
		return preHandlerEvents
	}

	handler := newCommandHandler(command)
	handler.Handle(command)
	handlerEvents := a.savePendingEvents(handler)

	return append(preHandlerEvents, handlerEvents...)
}

func (a *App) newClientApplicationAggregate(command Command) CommandHandler {
	return newClientApplication(a.eventsByStream(rangedb.GetEventStream(command)))
}

func (a *App) newResourceOwnerAggregate(command Command) CommandHandler {
	return newResourceOwner(
		a.eventsByStream(rangedb.GetEventStream(command)),
		a.tokenGenerator,
		a.clock,
	)
}

func (a *App) newAuthorizationCodeAggregate(command Command) CommandHandler {
	return newAuthorizationCode(
		a.eventsByStream(rangedb.GetEventStream(command)),
		a.tokenGenerator,
		a.clock,
	)
}

func (a *App) newRefreshTokenAggregate(command Command) CommandHandler {
	return newRefreshToken(
		a.eventsByStream(rangedb.GetEventStream(command)),
		a.tokenGenerator,
	)
}

func (a *App) eventsByStream(streamName string) <-chan *rangedb.Record {
	return a.store.EventsByStreamStartingWith(context.Background(), 0, streamName)
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
	a.store.SubscribeStartingWith(context.Background(), 0, subscribers...)
}

func resourceOwnerStream(userID string) string {
	return rangedb.GetEventStream(UserWasOnBoarded{UserID: userID})
}

func clientApplicationStream(clientID string) string {
	return rangedb.GetEventStream(ClientApplicationWasOnBoarded{ClientID: clientID})
}
