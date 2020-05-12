package projection

import (
	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
)

type clientApplication struct {
	ClientID        string
	ClientSecret    string
	CreateTimestamp uint64
}

type ClientApplications struct {
	clientApplications map[string]*clientApplication
}

func NewClientApplications() *ClientApplications {
	return &ClientApplications{
		clientApplications: make(map[string]*clientApplication),
	}
}

func (a *ClientApplications) Accept(record *rangedb.Record) {
	event, ok := record.Data.(*goauth2.ClientApplicationWasOnBoarded)
	if ok {
		a.clientApplications[event.ClientID] = &clientApplication{
			ClientID:        event.ClientID,
			ClientSecret:    event.ClientSecret,
			CreateTimestamp: record.InsertTimestamp,
		}
	}
}

func (a *ClientApplications) GetAll() []*clientApplication {
	var clientApplications []*clientApplication
	for _, clientApplication := range a.clientApplications {
		clientApplications = append(clientApplications, clientApplication)
	}
	return clientApplications
}
