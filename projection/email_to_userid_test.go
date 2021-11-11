package projection_test

import (
	"sync"
	"testing"

	"github.com/inklabs/rangedb/rangedbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/projection"
)

func TestEmailToUserID_Accept(t *testing.T) {
	// Given
	const (
		userID  = "881d60f1905d4457a611d596ae55d964"
		userID2 = "e0d0f5d7a72b432e8d553a0ac5c3d9b1"
		email   = "john@example.com"
	)

	t.Run("can get userID from email", func(t *testing.T) {
		// Given
		emailToUserID := projection.NewEmailToUserID()
		emailToUserID.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:   userID,
			Username: email,
		}))

		// When
		actualUserID, err := emailToUserID.GetUserID(email)

		// Then
		require.NoError(t, err)
		assert.Equal(t, userID, actualUserID)
	})

	t.Run("returns error for missing email", func(t *testing.T) {
		// Given
		emailToUserID := projection.NewEmailToUserID()
		emailToUserID.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:   userID,
			Username: email,
		}))

		// When
		actualUserID, err := emailToUserID.GetUserID("wrong-email@example.com")

		// Then
		assert.Equal(t, "", actualUserID)
		assert.Equal(t, err, projection.ErrUserNotFound)
	})

	t.Run("can get userID from email with duplicate email", func(t *testing.T) {
		// Given
		emailToUserID := projection.NewEmailToUserID()
		emailToUserID.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:   userID,
			Username: email,
		}))
		emailToUserID.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:   userID2,
			Username: email,
		}))

		// When
		actualUserID, err := emailToUserID.GetUserID(email)

		// Then
		require.NoError(t, err)
		assert.Equal(t, userID2, actualUserID)
	})

	t.Run("does not error from deadlock", func(t *testing.T) {
		// Given
		emailToUserID := projection.NewEmailToUserID()
		record1 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:   userID,
			Username: email,
		})
		record2 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:   userID2,
			Username: email,
		})
		var wg sync.WaitGroup
		wg.Add(2)

		// When
		go func() {
			emailToUserID.Accept(record1)
			wg.Done()
		}()
		emailToUserID.Accept(record2)
		wg.Done()

		// Then
		wg.Wait()
		actualUserID, err := emailToUserID.GetUserID(email)
		require.NoError(t, err)
		assert.Equal(t, userID, actualUserID)
	})
}
