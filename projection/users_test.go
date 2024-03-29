package projection_test

import (
	"sync"
	"testing"
	"time"

	"github.com/inklabs/rangedb/rangedbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/projection"
)

func TestUsers_Accept(t *testing.T) {
	// Given
	const (
		userID       = "e57252d9b7d6432bb089bc5cd86d12b3"
		username     = "john123"
		userID2      = "b1e9086e05bb43ceaf7f3173b76569e3"
		username2    = "jane456"
		passwordHash = "$2a$10$U6ej0p2d9Y8OO2635R7l/O4oEBvxgc9o6gCaQ1wjMZ77dr4qGl8nu"
		adminUserID  = "b8d9d4bf549d42a08ee3a730c983ae87"
	)
	issueTime := time.Date(2020, 05, 11, 8, 0, 0, 0, time.UTC)
	issueTime2 := time.Date(2020, 05, 12, 8, 0, 0, 0, time.UTC)

	t.Run("can get all users ordered by descending creation timestamp", func(t *testing.T) {
		// Given
		users := projection.NewUsers()
		record1 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     username,
			PasswordHash: passwordHash,
		})
		record2 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID2,
			Username:     username2,
			PasswordHash: passwordHash,
		})
		record1.InsertTimestamp = uint64(issueTime.Unix())
		record2.InsertTimestamp = uint64(issueTime2.Unix())
		users.Accept(record2)
		users.Accept(record1)

		// When
		actualUsers := users.GetAll()

		// Then
		assert.Len(t, actualUsers, 2)
		assert.Equal(t, userID2, actualUsers[0].UserID)
		assert.Equal(t, username2, actualUsers[0].Username)
		assert.Equal(t, uint64(issueTime2.Unix()), actualUsers[0].CreateTimestamp)
	})

	t.Run("can get all users ordered by creation timestamp, then by ascending userID", func(t *testing.T) {
		// Given
		users := projection.NewUsers()
		record1 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     username,
			PasswordHash: passwordHash,
		})
		record2 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID2,
			Username:     username2,
			PasswordHash: passwordHash,
		})
		users.Accept(record2)
		users.Accept(record1)

		// When
		actualUsers := users.GetAll()

		// Then
		assert.Len(t, actualUsers, 2)
		assert.Equal(t, userID2, actualUsers[0].UserID)
		assert.Equal(t, username2, actualUsers[0].Username)
	})

	t.Run("includes admin flag", func(t *testing.T) {
		// Given
		users := projection.NewUsers()
		users.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     username,
			PasswordHash: passwordHash,
		}))
		users.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasGrantedAdministratorRole{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}))

		// When
		actualUsers := users.GetAll()

		// Then
		assert.Len(t, actualUsers, 1)
		assert.Equal(t, userID, actualUsers[0].UserID)
		assert.True(t, actualUsers[0].IsAdmin)
	})

	t.Run("includes authorized to onboard client applications flag", func(t *testing.T) {
		// Given
		users := projection.NewUsers()
		users.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     username,
			PasswordHash: passwordHash,
		}))
		users.Accept(rangedbtest.DummyRecordFromEvent(&goauth2.UserWasAuthorizedToOnBoardClientApplications{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}))

		// When
		actualUsers := users.GetAll()

		// Then
		assert.Len(t, actualUsers, 1)
		assert.Equal(t, userID, actualUsers[0].UserID)
		assert.True(t, actualUsers[0].CanOnboardAdminApplications)
	})

	t.Run("returns empty list", func(t *testing.T) {
		// Given
		users := projection.NewUsers()

		// When
		actualUsers := users.GetAll()

		// Then
		assert.Len(t, actualUsers, 0)
	})

	t.Run("does not error from deadlock", func(t *testing.T) {
		// Given
		users := projection.NewUsers()
		record1 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     username,
			PasswordHash: passwordHash,
		})
		record2 := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
			UserID:       userID2,
			Username:     username2,
			PasswordHash: passwordHash,
		})
		var wg sync.WaitGroup
		wg.Add(2)

		// When
		go func() {
			users.Accept(record1)
			wg.Done()
		}()
		users.Accept(record2)
		wg.Done()

		// Then
		wg.Wait()
		actualUsers := users.GetAll()
		assert.Len(t, actualUsers, 2)
	})

	t.Run("Get", func(t *testing.T) {
		t.Run("returns user by userID", func(t *testing.T) {
			// Given
			users := projection.NewUsers()
			record := rangedbtest.DummyRecordFromEvent(&goauth2.UserWasOnBoarded{
				UserID:         userID,
				Username:       username,
				PasswordHash:   passwordHash,
				GrantingUserID: adminUserID,
			})
			users.Accept(record)

			// When
			actualUser, err := users.Get(userID)

			// Then
			require.NoError(t, err)
			assert.Equal(t, userID, actualUser.UserID)
			assert.Equal(t, username, actualUser.Username)
			assert.Equal(t, adminUserID, actualUser.GrantingUserID)
			assert.False(t, actualUser.IsAdmin)
			assert.False(t, actualUser.CanOnboardAdminApplications)
		})

		t.Run("returns user not found", func(t *testing.T) {
			// Given
			const notFoundID = "af5aa3e15b2a47aca0f5af0e7437ce3f"
			users := projection.NewUsers()

			// When
			actualUser, err := users.Get(notFoundID)

			// Then
			assert.Nil(t, actualUser)
			assert.Equal(t, projection.ErrUserNotFound, err)
		})
	})
}
