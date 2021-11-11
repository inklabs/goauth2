package projection

import (
	"sort"
	"sync"

	"github.com/inklabs/rangedb"

	"github.com/inklabs/goauth2"
)

type clientApplication struct {
	ClientID        string
	ClientSecret    string
	CreateTimestamp uint64
}

// ClientApplications is a projection containing a list of all client applications.
type ClientApplications struct {
	mu                 sync.RWMutex
	clientApplications map[string]*clientApplication
}

// NewClientApplications constructs a new ClientApplications projection.
func NewClientApplications() *ClientApplications {
	return &ClientApplications{
		clientApplications: make(map[string]*clientApplication),
	}
}

// Accept receives a rangedb.Record.
func (a *ClientApplications) Accept(record *rangedb.Record) {
	event, ok := record.Data.(*goauth2.ClientApplicationWasOnBoarded)
	if ok {
		a.mu.Lock()
		defer a.mu.Unlock()

		a.clientApplications[event.ClientID] = &clientApplication{
			ClientID:        event.ClientID,
			ClientSecret:    event.ClientSecret,
			CreateTimestamp: record.InsertTimestamp,
		}
	}
}

// GetAll returns client applications sorted by most recent creation timestamp
func (a *ClientApplications) GetAll() []*clientApplication {
	a.mu.RLock()

	var clientApplications []*clientApplication
	for _, clientApplication := range a.clientApplications {
		clientApplications = append(clientApplications, clientApplication)
	}

	a.mu.RUnlock()

	sort.SliceStable(clientApplications, func(i, j int) bool {
		return clientApplications[i].CreateTimestamp >= clientApplications[j].CreateTimestamp
	})

	return clientApplications
}
