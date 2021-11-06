package projection_test

import (
	"sync"
	"testing"
	"time"

	"github.com/inklabs/rangedb/rangedbtest"
	"github.com/stretchr/testify/assert"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/projection"
)

func TestClientApplications_Accept(t *testing.T) {
	// Given
	const (
		clientID     = "f9236197e7f24ef994cbe2e06e026f24"
		clientSecret = "5970aca5e64d4f5e9e7842db8796619f"
		userID       = "e171f450626644fa8656b037c42bbf11"
		redirectURI  = "http://example.com/oauth2/callback"
		clientID2    = "0e3c58dd233b43c0aba4fa7578b9aba0"
	)
	issueTime := time.Date(2020, 05, 11, 8, 0, 0, 0, time.UTC)

	t.Run("can get all client applications", func(t *testing.T) {
		// Given
		clientApplications := projection.NewClientApplications()
		record := rangedbtest.DummyRecordFromEvent(&goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       userID,
		})
		record.InsertTimestamp = uint64(issueTime.Unix())
		clientApplications.Accept(record)

		// When
		actualClientApplications := clientApplications.GetAll()

		// Then
		assert.Len(t, actualClientApplications, 1)
		assert.Equal(t, clientID, actualClientApplications[0].ClientID)
		assert.Equal(t, clientSecret, actualClientApplications[0].ClientSecret)
		assert.Equal(t, uint64(issueTime.Unix()), actualClientApplications[0].CreateTimestamp)
	})

	t.Run("returns empty list", func(t *testing.T) {
		// Given
		clientApplications := projection.NewClientApplications()

		// When
		actualClientApplications := clientApplications.GetAll()

		// Then
		assert.Len(t, actualClientApplications, 0)
	})

	t.Run("does not error from deadlock", func(t *testing.T) {
		// Given
		clientApplications := projection.NewClientApplications()
		record1 := rangedbtest.DummyRecordFromEvent(&goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       userID,
		})
		record2 := rangedbtest.DummyRecordFromEvent(&goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID2,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       userID,
		})
		var wg sync.WaitGroup
		wg.Add(2)

		// When
		go func() {
			clientApplications.Accept(record1)
			wg.Done()
		}()
		clientApplications.Accept(record2)
		wg.Done()

		// Then
		wg.Wait()
		actualClientApplications := clientApplications.GetAll()
		assert.Len(t, actualClientApplications, 2)
	})
}
