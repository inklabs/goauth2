package projection_test

import (
	"testing"
	"time"

	"github.com/inklabs/rangedb/rangedbtest"
	"github.com/stretchr/testify/assert"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/projection"
)

func TestUsers_Accept(t *testing.T) {
	// Given
	const (
		userID       = "e57252d9b7d6432bb089bc5cd86d12b3"
		username     = "john123"
		passwordHash = "$2a$10$U6ej0p2d9Y8OO2635R7l/O4oEBvxgc9o6gCaQ1wjMZ77dr4qGl8nu"
	)
	issueTime := time.Date(2020, 05, 11, 8, 0, 0, 0, time.UTC)

	t.Run("can get all users", func(t *testing.T) {
		// Given
		users := projection.NewUsers()
		record := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     username,
			PasswordHash: passwordHash,
		})
		record.InsertTimestamp = uint64(issueTime.Unix())
		users.Accept(record)

		// When
		actualUsers := users.GetAll()

		// Then
		assert.Len(t, actualUsers, 1)
		assert.Equal(t, userID, actualUsers[0].UserID)
		assert.Equal(t, username, actualUsers[0].Username)
		assert.Equal(t, uint64(issueTime.Unix()), actualUsers[0].CreateTimestamp)
	})

	t.Run("returns empty list", func(t *testing.T) {
		// Given
		users := projection.NewUsers()

		// When
		actualUsers := users.GetAll()

		// Then
		assert.Len(t, actualUsers, 0)
	})
}
