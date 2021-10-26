package goauth2

import (
	"net/url"

	"github.com/inklabs/rangedb"
)

func ClientApplicationCommandTypes() []string {
	return []string{
		OnBoardClientApplication{}.CommandType(),
		RequestAccessTokenViaClientCredentialsGrant{}.CommandType(),
	}
}

type clientApplication struct {
	IsOnBoarded   bool
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	pendingEvents []rangedb.Event
}

func newClientApplication(iter rangedb.RecordIterator) *clientApplication {
	aggregate := &clientApplication{}

	for iter.Next() {
		if event, ok := iter.Record().Data.(rangedb.Event); ok {
			aggregate.apply(event)
		}
	}

	return aggregate
}

func (a *clientApplication) apply(event rangedb.Event) {
	switch e := event.(type) {
	case *ClientApplicationWasOnBoarded:
		a.IsOnBoarded = true
		a.ClientID = e.ClientID
		a.ClientSecret = e.ClientSecret
		a.RedirectURI = e.RedirectURI

	}
}

func (a *clientApplication) GetPendingEvents() []rangedb.Event {
	return a.pendingEvents
}

func (a *clientApplication) Handle(command Command) {
	switch c := command.(type) {

	case OnBoardClientApplication:
		a.OnBoardClientApplication(c)

	case RequestAccessTokenViaClientCredentialsGrant:
		a.RequestAccessTokenViaClientCredentialsGrant(c)

	}
}

func (a *clientApplication) OnBoardClientApplication(c OnBoardClientApplication) {
	uri, err := url.Parse(c.RedirectURI)
	if err != nil {
		a.raise(OnBoardClientApplicationWasRejectedDueToInvalidRedirectURI{
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
		})
		return
	}

	if uri.Scheme != "https" {
		a.raise(OnBoardClientApplicationWasRejectedDueToInsecureRedirectURI{
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
		})
		return
	}

	a.raise(ClientApplicationWasOnBoarded{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		UserID:       c.UserID,
	})
}

func (a *clientApplication) RequestAccessTokenViaClientCredentialsGrant(c RequestAccessTokenViaClientCredentialsGrant) {
	if !a.IsOnBoarded {
		a.raise(RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationID{
			ClientID: c.ClientID,
		})
		return
	}

	if a.ClientSecret != c.ClientSecret {
		a.raise(RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationSecret{
			ClientID: c.ClientID,
		})
		return
	}

	a.raise(AccessTokenWasIssuedToClientApplicationViaClientCredentialsGrant{
		ClientID: c.ClientID,
	})
}

func (a *clientApplication) raise(events ...rangedb.Event) {
	for _, event := range events {
		a.apply(event)
	}

	a.pendingEvents = append(a.pendingEvents, events...)
}
