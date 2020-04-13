package projection_test

import (
	"testing"

	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/inklabs/rangedb/provider/jsonrecordserializer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/projection"
)

const (
	userID  = "881d60f1905d4457a611d596ae55d964"
	userID2 = "e0d0f5d7a72b432e8d553a0ac5c3d9b1"
	email   = "john@example.com"
)

func TestEmailToUserID_Accept(t *testing.T) {
	serializer := jsonrecordserializer.New()
	goauth2.BindEvents(serializer)

	t.Run("can get userID from email", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		emailToUserID := projection.NewEmailToUserID()
		store.Subscribe(emailToUserID)
		require.NoError(t, store.Save(goauth2.UserWasOnBoarded{
			UserID:   userID,
			Username: email,
		}, nil))

		// When
		actualUserID, err := emailToUserID.GetUserID(email)

		// Then
		require.NoError(t, err)
		assert.Equal(t, userID, actualUserID)
	})

	t.Run("returns error for missing email", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		emailToUserID := projection.NewEmailToUserID()
		store.Subscribe(emailToUserID)
		require.NoError(t, store.Save(goauth2.UserWasOnBoarded{
			UserID:   userID,
			Username: email,
		}, nil))

		// When
		actualUserID, err := emailToUserID.GetUserID("wrong-email@example.com")

		// Then
		assert.Equal(t, "", actualUserID)
		assert.Equal(t, err, projection.UserNotFound)
	})

	t.Run("can get userID from email with duplicate email", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		emailToUserID := projection.NewEmailToUserID()
		store.Subscribe(emailToUserID)
		require.NoError(t, store.Save(goauth2.UserWasOnBoarded{
			UserID:   userID,
			Username: email,
		}, nil))
		require.NoError(t, store.Save(goauth2.UserWasOnBoarded{
			UserID:   userID2,
			Username: email,
		}, nil))

		// When
		actualUserID, err := emailToUserID.GetUserID(email)

		// Then
		require.NoError(t, err)
		assert.Equal(t, userID2, actualUserID)
	})
}
