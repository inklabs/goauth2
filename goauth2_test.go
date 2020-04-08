package goauth2_test

import (
	"testing"

	"github.com/inklabs/rangedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
)

const (
	clientID     = "7d327d51d1304341a21c1242fcb089f4"
	clientSecret = "c389e799ac0e4568b1c4b4c96b670605"
	redirectUri  = "https://example.com/oauth2/callback"
	userID       = "d904f8dbd4684a6591a24c8e67ea4a77"
	adminUserID  = "7dd7157576e5426ebf44e387d80f0538"
	email        = "john@example.com"
	passwordHash = "$2a$10$U6ej0p2d9Y8OO2635R7l/O4oEBvxgc9o6gCaQ1wjMZ77dr4qGl8nu"
	password     = "Pass123!"
)

func Test_OnBoardUser(t *testing.T) {
	t.Run("on-boards user", goauth2TestCase().
		Given().
		When(goauth2.OnBoardUser{
			UserID:   userID,
			Username: email,
			Password: password,
		}).
		ThenInspectEvents(func(t *testing.T, events []rangedb.Event) {
			require.Equal(t, 1, len(events))
			event := events[0].(goauth2.UserWasOnBoarded)
			assert.Equal(t, userID, event.UserID)
			assert.Equal(t, email, event.Username)
			assert.True(t, goauth2.VerifyPassword(event.PasswordHash, password))
		}))

	t.Run("rejected due to existing user", goauth2TestCase().
		Given(goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     email,
			PasswordHash: passwordHash,
		}).
		When(goauth2.OnBoardUser{
			UserID:   userID,
			Username: email,
			Password: password,
		}).
		Then(goauth2.OnBoardUserWasRejectedDueToExistingUser{
			UserID: userID,
		}))

	t.Run("rejected due to insecure password", goauth2TestCase().
		Given().
		When(goauth2.OnBoardUser{
			UserID:   userID,
			Username: email,
			Password: "password",
		}).
		Then(goauth2.OnBoardUserWasRejectedDueToInsecurePassword{
			UserID: userID,
		}))
}

func Test_GrantUserAdministratorRole(t *testing.T) {
	t.Run("user was granted administrator role", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       adminUserID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasGrantedAdministratorRole{
				UserID:         adminUserID,
				GrantingUserID: adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.GrantUserAdministratorRole{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}).
		Then(goauth2.UserWasGrantedAdministratorRole{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}))

	t.Run("rejected due to missing granting user", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.GrantUserAdministratorRole{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}).
		Then(goauth2.GrantUserAdministratorRoleWasRejectedDueToMissingGrantingUser{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}))

	t.Run("rejected due to non-administrator granting user", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       adminUserID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.GrantUserAdministratorRole{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}).
		Then(goauth2.GrantUserAdministratorRoleWasRejectedDueToNonAdministrator{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}))

	t.Run("rejected due to missing target user", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       adminUserID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasGrantedAdministratorRole{
				UserID:         adminUserID,
				GrantingUserID: adminUserID,
			},
		).
		When(goauth2.GrantUserAdministratorRole{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}).
		Then(goauth2.GrantUserAdministratorRoleWasRejectedDueToMissingTargetUser{
			UserID:         userID,
			GrantingUserID: adminUserID,
		}))
}

func Test_RequestAccessTokenViaClientCredentialsGrant(t *testing.T) {
	t.Run("issue access token for on-boarded client application", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectUri:  redirectUri,
			UserID:       adminUserID,
		}).
		When(goauth2.RequestAccessTokenViaClientCredentialsGrant{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(goauth2.AccessTokenWasIssuedToClientApplicationViaClientCredentialsGrant{
			ClientID: clientID,
		}))

	t.Run("rejected due to missing client application", goauth2TestCase().
		Given().
		When(goauth2.RequestAccessTokenViaClientCredentialsGrant{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(goauth2.RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationID{
			ClientID: clientID,
		}))

	t.Run("rejected due to wrong client application secret", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectUri:  redirectUri,
			UserID:       adminUserID,
		}).
		When(goauth2.RequestAccessTokenViaClientCredentialsGrant{
			ClientID:     clientID,
			ClientSecret: "wrong-secret",
		}).
		Then(goauth2.RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationSecret{
			ClientID: clientID,
		}))
}
