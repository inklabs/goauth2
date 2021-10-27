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

// Version for Go OAuth2.
const Version = "0.1.0-dev"

// App is the OAuth2 CQRS application.
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

// WithClock is a functional option to inject a clock.
func WithClock(clock clock.Clock) Option {
	return func(app *App) {
		app.clock = clock
	}
}

// WithStore is a functional option to inject a RangeDB Event Store.
func WithStore(store rangedb.Store) Option {
	return func(app *App) {
		app.store = store
	}
}

// WithTokenGenerator is a functional option to inject a token generator.
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

// New constructs an OAuth2 CQRS application.
func New(options ...Option) (*App, error) {
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

	app.registerPreCommandHandler(newClientApplicationCommandAuthorization(app.store, app.clock))
	app.registerPreCommandHandler(newResourceOwnerCommandAuthorization(app.store, app.tokenGenerator, app.clock))

	app.registerCommandHandler(ResourceOwnerCommandTypes(), app.newResourceOwnerAggregate)
	app.registerCommandHandler(ClientApplicationCommandTypes(), app.newClientApplicationAggregate)
	app.registerCommandHandler(AuthorizationCodeCommandTypes(), app.newAuthorizationCodeAggregate)
	app.registerCommandHandler(RefreshTokenCommandTypes(), app.newRefreshTokenAggregate)

	authorizationCodeRefreshTokens := NewAuthorizationCodeRefreshTokens()
	err := app.SubscribeAndReplay(authorizationCodeRefreshTokens)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	subscribers := newMultipleSubscriber(
		newRefreshTokenProcessManager(app.Dispatch, authorizationCodeRefreshTokens),
		newAuthorizationCodeProcessManager(app.Dispatch),
	)
	subscriber := app.store.AllEventsSubscription(ctx, 10, subscribers)
	err = subscriber.Start()
	if err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) registerPreCommandHandler(handler PreCommandHandler) {
	for _, commandType := range handler.CommandTypes() {
		a.preCommandHandlers[commandType] = append(a.preCommandHandlers[commandType], handler)
	}
}

func (a *App) registerCommandHandler(commandTypes []string, factory CommandHandlerFactory) {
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
	return newClientApplication(a.eventsByStream(rangedb.GetEventStream(command)), a.clock)
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
		a.clock,
	)
}

func (a *App) eventsByStream(streamName string) rangedb.RecordIterator {
	return a.store.EventsByStream(context.Background(), 0, streamName)
}

func (a *App) savePendingEvents(events PendingEvents) []rangedb.Event {
	pendingEvents := events.GetPendingEvents()
	ctx := context.Background()
	for _, event := range pendingEvents {
		_, err := a.store.Save(ctx, &rangedb.EventRecord{
			Event: event,
		})
		if err != nil {
			a.logger.Printf("unable to save event: %v", err)
		}
	}
	return pendingEvents
}

func (a *App) SubscribeAndReplay(subscribers ...rangedb.RecordSubscriber) error {
	ctx := context.Background()
	subscription := a.store.AllEventsSubscription(ctx, 50, newMultipleSubscriber(subscribers...))
	err := subscription.StartFrom(0)
	if err != nil {
		return err
	}

	return nil
}

func resourceOwnerStream(userID string) string {
	return rangedb.GetEventStream(UserWasOnBoarded{UserID: userID})
}

func clientApplicationStream(clientID string) string {
	return rangedb.GetEventStream(ClientApplicationWasOnBoarded{ClientID: clientID})
}

type multipleSubscriber struct {
	subscribers []rangedb.RecordSubscriber
}

func newMultipleSubscriber(subscribers ...rangedb.RecordSubscriber) *multipleSubscriber {
	return &multipleSubscriber{
		subscribers: subscribers,
	}
}

func (m multipleSubscriber) Accept(record *rangedb.Record) {
	for _, subscriber := range m.subscribers {
		subscriber.Accept(record)
	}
}
