package goauth2_test

import (
	"bytes"
	"log"
	"testing"
	"time"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/clock/provider/seededclock"
	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/inklabs/rangedb/rangedbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/goauth2test"
)

const (
	clientID            = "7d327d51d1304341a21c1242fcb089f4"
	clientSecret        = "c389e799ac0e4568b1c4b4c96b670605"
	clientID2           = "a09bb83c916a449c9e396561506b9a26"
	clientSecret2       = "54963344349742c098e0904137202bcb"
	redirectURI         = "https://example.com/oauth2/callback"
	wrongRedirectURI    = "https://example.com/wrong/redirect/uri"
	invalidRedirectURI  = "://invalid-uri"
	insecureRedirectURI = "http://example.com/oauth2/callback"
	userID              = "d904f8dbd4684a6591a24c8e67ea4a77"
	adminUserID         = "7dd7157576e5426ebf44e387d80f0538"
	email               = "john@example.com"
	adminEmail          = "admin@example.com"
	passwordHash        = "$2a$10$U6ej0p2d9Y8OO2635R7l/O4oEBvxgc9o6gCaQ1wjMZ77dr4qGl8nu"
	password            = "Pass123!"
	scope               = "read_write"
	refreshToken        = "1eff35434eee448884a2d7e2dd28b119"
	nextRefreshToken    = "18cb764961464db9b259550c6568fa4d"
	authorizationCode   = "afa410b917034f67b64ec9164bf4140d"
)

var (
	issueTime              = time.Date(2020, 04, 1, 8, 0, 0, 0, time.UTC)
	issueTimePlus9Minutes  = issueTime.Add(9 * time.Minute)
	issueTimePlus10Minutes = issueTime.Add(10 * time.Minute)
	issueTimePlus11Minutes = issueTime.Add(11 * time.Minute)
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

	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", 0)
	t.Run("fails when store cannot save events", goauth2TestCase(
		goauth2.WithStore(rangedbtest.NewFailingEventStore()),
		goauth2.WithLogger(logger),
	).
		Given().
		When(goauth2.OnBoardUser{
			UserID:   userID,
			Username: email,
			Password: password,
		}).
		ThenInspectEvents(func(t *testing.T, events []rangedb.Event) {
			require.Equal(t, 0, len(events))
			assert.Equal(t, "unable to save event: failingEventStore.Save\n", logBuffer.String())
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

func Test_AuthorizeUserToOnBoardClientApplications(t *testing.T) {
	t.Run("user is authorized to on-board client applications", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       adminUserID,
				Username:     adminEmail,
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
		When(goauth2.AuthorizeUserToOnBoardClientApplications{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}).
		Then(goauth2.UserWasAuthorizedToOnBoardClientApplications{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}))

	t.Run("rejected due to missing authorized user", goauth2TestCase().
		Given(goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     email,
			PasswordHash: passwordHash,
		}).
		When(goauth2.AuthorizeUserToOnBoardClientApplications{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}).
		Then(goauth2.AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingAuthorizingUser{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}))

	t.Run("rejected due to non-administrator user", goauth2TestCase().
		Given(goauth2.UserWasOnBoarded{
			UserID:       adminUserID,
			Username:     adminEmail,
			PasswordHash: passwordHash,
		}).
		When(goauth2.AuthorizeUserToOnBoardClientApplications{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}).
		Then(goauth2.AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToNonAdministrator{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}))

	t.Run("rejected due to missing target user", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       adminUserID,
				Username:     adminEmail,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasGrantedAdministratorRole{
				UserID:         adminUserID,
				GrantingUserID: adminUserID,
			},
		).
		When(goauth2.AuthorizeUserToOnBoardClientApplications{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}).
		Then(goauth2.AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingTargetUser{
			UserID:            userID,
			AuthorizingUserID: adminUserID,
		}))
}

func Test_OnBoardClientApplication(t *testing.T) {
	t.Run("on-boards client application", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasAuthorizedToOnBoardClientApplications{
				UserID:            userID,
				AuthorizingUserID: adminUserID,
			},
		).
		When(goauth2.OnBoardClientApplication{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       userID,
		}).
		Then(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       userID,
		}))

	t.Run("rejected due to missing user", goauth2TestCase().
		Given().
		When(goauth2.OnBoardClientApplication{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       userID,
		}).
		Then(goauth2.OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
			ClientID: clientID,
			UserID:   userID,
		}))

	t.Run("rejected due to unauthorized user", goauth2TestCase().
		Given(goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     email,
			PasswordHash: passwordHash,
		}).
		When(goauth2.OnBoardClientApplication{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       userID,
		}).
		Then(goauth2.OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser{
			ClientID: clientID,
			UserID:   userID,
		}))

	t.Run("rejected due to invalid redirect URI", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasAuthorizedToOnBoardClientApplications{
				UserID:            userID,
				AuthorizingUserID: adminUserID,
			},
		).
		When(goauth2.OnBoardClientApplication{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  invalidRedirectURI,
			UserID:       userID,
		}).
		Then(goauth2.OnBoardClientApplicationWasRejectedDueToInvalidRedirectURI{
			ClientID:    clientID,
			RedirectURI: invalidRedirectURI,
		}))

	t.Run("rejected due to insecure redirect URI", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.UserWasAuthorizedToOnBoardClientApplications{
				UserID:            userID,
				AuthorizingUserID: adminUserID,
			},
		).
		When(goauth2.OnBoardClientApplication{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  insecureRedirectURI,
			UserID:       userID,
		}).
		Then(goauth2.OnBoardClientApplicationWasRejectedDueToInsecureRedirectURI{
			ClientID:    clientID,
			RedirectURI: insecureRedirectURI,
		}))
}

func Test_RequestAccessTokenViaImplicitGrant(t *testing.T) {
	t.Run("access token is issued", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    password,
		}).
		Then(goauth2.AccessTokenWasIssuedToUserViaImplicitGrant{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to invalid client application id", goauth2TestCase().
		Given(goauth2.UserWasOnBoarded{
			UserID:       userID,
			Username:     email,
			PasswordHash: passwordHash,
		}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    password,
		}).
		Then(goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationID{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to invalid client application redirect uri", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: wrongRedirectURI,
			Username:    email,
			Password:    password,
		}).
		Then(goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: wrongRedirectURI,
		}))

	t.Run("rejected due to missing user", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    password,
		}).
		Then(goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUser{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to invalid user password", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    "wrong-password",
		}).
		Then(goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUserPassword{
			UserID:   userID,
			ClientID: clientID,
		}))
}

func Test_RequestAccessTokenViaROPCGrant(t *testing.T) {
	t.Run("access and refresh tokens are issued", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
	).
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
		).
		When(goauth2.RequestAccessTokenViaROPCGrant{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Username:     email,
			Password:     password,
			Scope:        scope,
		}).
		Then(
			goauth2.AccessTokenWasIssuedToUserViaROPCGrant{
				UserID:   userID,
				ClientID: clientID,
			},
			goauth2.RefreshTokenWasIssuedToUserViaROPCGrant{
				UserID:       userID,
				ClientID:     clientID,
				RefreshToken: refreshToken,
				Scope:        scope,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		))

	t.Run("rejected due to missing client application id", goauth2TestCase().
		Given().
		When(goauth2.RequestAccessTokenViaROPCGrant{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Username:     email,
			Password:     password,
		}).
		Then(goauth2.RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to invalid client application secret", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		}).
		When(goauth2.RequestAccessTokenViaROPCGrant{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: "wrong-client-secret",
			Username:     email,
			Password:     password,
		}).
		Then(goauth2.RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to missing user", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		}).
		When(goauth2.RequestAccessTokenViaROPCGrant{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Username:     email,
			Password:     password,
		}).
		Then(goauth2.RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUser{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to invalid user password", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
		).
		When(goauth2.RequestAccessTokenViaROPCGrant{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Username:     email,
			Password:     "wrong-password",
		}).
		Then(goauth2.RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUserPassword{
			UserID:   userID,
			ClientID: clientID,
		}))
}

func Test_RequestAccessTokenViaClientCredentialsGrant(t *testing.T) {
	t.Run("issue access token for on-boarded client application", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
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
			RedirectURI:  redirectURI,
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

func Test_RequestAccessTokenViaRefreshTokenGrant_For_User(t *testing.T) {
	t.Run("access and refresh tokens are issued to user", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(nextRefreshToken)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scope:        scope,
		}).
		Then(
			goauth2.AccessTokenWasIssuedToUserViaRefreshTokenGrant{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
			},
			goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
				RefreshToken:     refreshToken,
				UserID:           userID,
				ClientID:         clientID,
				NextRefreshToken: nextRefreshToken,
				Scope:            scope,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: nextRefreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		))

	t.Run("access and refresh tokens are issued to user without providing scope", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(nextRefreshToken)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(
			goauth2.AccessTokenWasIssuedToUserViaRefreshTokenGrant{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
			},
			goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
				RefreshToken:     refreshToken,
				UserID:           userID,
				ClientID:         clientID,
				NextRefreshToken: nextRefreshToken,
				Scope:            scope,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: nextRefreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		))

	t.Run("rejected due to missing client application", goauth2TestCase().
		Given().
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(goauth2.RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidClientApplicationCredentials{
			RefreshToken: refreshToken,
			ClientID:     clientID,
		}))

	t.Run("rejected due to invalid client application credentials", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		}).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: "wrong-client-secret",
		}).
		Then(goauth2.RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidClientApplicationCredentials{
			RefreshToken: refreshToken,
			ClientID:     clientID,
		}))

	t.Run("rejected due to invalid refresh token", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(goauth2.RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidRefreshToken{
			RefreshToken: refreshToken,
			ClientID:     clientID,
		}))

	t.Run("rejected due to invalid scope", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scope:        "invalid-scope",
		}).
		Then(goauth2.RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidScope{
			RefreshToken:   refreshToken,
			ClientID:       clientID,
			Scope:          scope,
			RequestedScope: "invalid-scope",
		}))

	t.Run("rejected due to previously used refresh token", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
			goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
				RefreshToken:     refreshToken,
				UserID:           userID,
				NextRefreshToken: nextRefreshToken,
			},
		).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(goauth2.RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToPreviouslyUsedRefreshToken{
			RefreshToken: refreshToken,
		}))

	t.Run("rejected due to revoked refresh token", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
			goauth2.RefreshTokenWasRevokedFromUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
			},
		).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(goauth2.RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToRevokedRefreshToken{
			RefreshToken: refreshToken,
			ClientID:     clientID,
		}))
}

func Test_RequestAccessTokenViaRefreshTokenGrant_For_ClientApplication(t *testing.T) {
	t.Run("access and refresh tokens are issued to client application", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(nextRefreshToken)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.RefreshTokenWasIssuedToClientApplication{
				RefreshToken: refreshToken,
				ClientID:     clientID,
			},
		).
		When(goauth2.RequestAccessTokenViaRefreshTokenGrant{
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		Then(
			goauth2.AccessTokenWasIssuedToClientApplicationViaRefreshTokenGrant{
				RefreshToken: refreshToken,
				ClientID:     clientID,
			},
			goauth2.RefreshTokenWasIssuedToClientApplicationViaRefreshTokenGrant{
				RefreshToken:     refreshToken,
				ClientID:         clientID,
				NextRefreshToken: nextRefreshToken,
			},
		))
}

func Test_RequestAuthorizationCodeViaAuthorizationCodeGrant(t *testing.T) {
	t.Run("issues authorization code to user", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(authorizationCode)),
		goauth2.WithClock(seededclock.New(issueTime)),
	).
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
		).
		When(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    password,
			Scope:       scope,
		}).
		Then(
			goauth2.AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant{
				UserID:            userID,
				ClientID:          clientID,
				AuthorizationCode: authorizationCode,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
			goauth2.AuthorizationCodeWasIssuedToUser{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
		))

	t.Run("rejected due to missing client application id", goauth2TestCase().
		Given().
		When(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    password,
			Scope:       scope,
		}).
		Then(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to invalid client application redirect uri", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		}).
		When(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: wrongRedirectURI,
			Username:    email,
			Password:    password,
			Scope:       scope,
		}).
		Then(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: wrongRedirectURI,
		}))

	t.Run("rejected due to missing user", goauth2TestCase().
		Given(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			UserID:       adminUserID,
		}).
		When(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    password,
			Scope:       scope,
		}).
		Then(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUser{
			UserID:   userID,
			ClientID: clientID,
		}))

	t.Run("rejected due to invalid user password", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
		).
		When(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    email,
			Password:    "wrong-password",
			Scope:       scope,
		}).
		Then(goauth2.RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUserPassword{
			UserID:   userID,
			ClientID: clientID,
		}))
}

func Test_RequestAccessTokenViaAuthorizationCodeGrant(t *testing.T) {
	t.Run("issues access and refresh token to user", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
		goauth2.WithClock(seededclock.New(issueTimePlus9Minutes)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.AuthorizationCodeWasIssuedToUser{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(
			goauth2.AccessTokenWasIssuedToUserViaAuthorizationCodeGrant{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				Scope:             scope,
			},
			goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				RefreshToken:      refreshToken,
				Scope:             scope,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		))

	t.Run("rejected due to invalid client application id", goauth2TestCase().
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
		}))

	t.Run("rejected due to invalid client application secret", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      "wrong-secret",
			RedirectURI:       redirectURI,
		}).
		Then(goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationSecret{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
		}))

	t.Run("rejected due to invalid client application redirect uri", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       wrongRedirectURI,
		}).
		Then(goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			RedirectURI:       wrongRedirectURI,
		}))

	t.Run("rejected due to unmatched client application id", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID2,
				ClientSecret: clientSecret2,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.AuthorizationCodeWasIssuedToUser{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID2,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToUnmatchedClientApplicationID{
			AuthorizationCode: authorizationCode,
			RequestedClientID: clientID,
			ActualClientID:    clientID2,
		}))

	t.Run("rejected due to invalid authorization code", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidAuthorizationCode{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
		}))

	t.Run("rejected due to expired authorization code", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
		goauth2.WithClock(seededclock.New(issueTimePlus11Minutes)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.AuthorizationCodeWasIssuedToUser{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToExpiredAuthorizationCode{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
		}))

	t.Run("rejected due to previously used authorization code from access token", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
		goauth2.WithClock(seededclock.New(issueTimePlus9Minutes)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.AuthorizationCodeWasIssuedToUser{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
			goauth2.AccessTokenWasIssuedToUserViaAuthorizationCodeGrant{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				Scope:             scope,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			UserID:            userID,
		}))

	t.Run("rejected due to previously used authorization code with one refresh token", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
		goauth2.WithClock(seededclock.New(issueTimePlus9Minutes)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.AuthorizationCodeWasIssuedToUser{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
			goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
				AuthorizationCode: authorizationCode,
				ClientID:          clientID,
				UserID:            userID,
				RefreshToken:      refreshToken,
				Scope:             scope,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(
			goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode{
				AuthorizationCode: authorizationCode,
				ClientID:          clientID,
				UserID:            userID,
			},
			goauth2.RefreshTokenWasRevokedFromUser{
				RefreshToken: refreshToken,
				ClientID:     clientID,
				UserID:       userID,
			},
		))

	t.Run("rejected due to previously used authorization code with two refresh tokens", goauth2TestCase(
		goauth2.WithTokenGenerator(goauth2test.NewSeededTokenGenerator(refreshToken)),
		goauth2.WithClock(seededclock.New(issueTimePlus9Minutes)),
	).
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURI:  redirectURI,
				UserID:       adminUserID,
			},
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.AuthorizationCodeWasIssuedToUser{
				AuthorizationCode: authorizationCode,
				UserID:            userID,
				ClientID:          clientID,
				ExpiresAt:         issueTimePlus10Minutes.Unix(),
				Scope:             scope,
			},
			goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
				AuthorizationCode: authorizationCode,
				ClientID:          clientID,
				UserID:            userID,
				RefreshToken:      refreshToken,
				Scope:             scope,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: refreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
			goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
				RefreshToken:     refreshToken,
				UserID:           userID,
				ClientID:         clientID,
				NextRefreshToken: nextRefreshToken,
				Scope:            scope,
			},
			goauth2.RefreshTokenWasIssuedToUser{
				RefreshToken: nextRefreshToken,
				UserID:       userID,
				ClientID:     clientID,
				Scope:        scope,
			},
		).
		When(goauth2.RequestAccessTokenViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			RedirectURI:       redirectURI,
		}).
		Then(
			goauth2.RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode{
				AuthorizationCode: authorizationCode,
				ClientID:          clientID,
				UserID:            userID,
			},
			goauth2.RefreshTokenWasRevokedFromUser{
				RefreshToken: refreshToken,
				ClientID:     clientID,
				UserID:       userID,
			},
			goauth2.RefreshTokenWasRevokedFromUser{
				RefreshToken: nextRefreshToken,
				ClientID:     clientID,
				UserID:       userID,
			},
		))
}

func TestEventsAreBoundProperly(t *testing.T) {
	t.Run("by default", func(t *testing.T) {
		// Given
		app, err := goauth2.New()
		require.NoError(t, err)
		recorder := &eventRecorder{}
		blockingSubscriber := rangedbtest.NewBlockingSubscriber(recorder)
		require.NoError(t, app.SubscribeAndReplay(blockingSubscriber))

		// When
		events := app.Dispatch(goauth2.OnBoardUser{
			UserID:   userID,
			Username: email,
			Password: password,
		})

		// Then
		rangedbtest.ReadRecord(t, blockingSubscriber.Records)
		require.Len(t, recorder.Records, 1)
		assert.IsType(t, &goauth2.UserWasOnBoarded{}, recorder.Records[0].Data)
		require.Len(t, events, 1)
		assert.IsType(t, goauth2.UserWasOnBoarded{}, events[0])
	})

	t.Run("when injecting a store", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		app, err := goauth2.New(goauth2.WithStore(store))
		require.NoError(t, err)
		recorder := &eventRecorder{}
		blockingSubscriber := rangedbtest.NewBlockingSubscriber(recorder)
		require.NoError(t, app.SubscribeAndReplay(blockingSubscriber))

		// When
		events := app.Dispatch(goauth2.OnBoardUser{
			UserID:   userID,
			Username: email,
			Password: password,
		})

		// Then
		rangedbtest.ReadRecord(t, blockingSubscriber.Records)
		require.Len(t, recorder.Records, 1)
		assert.IsType(t, &goauth2.UserWasOnBoarded{}, recorder.Records[0].Data)
		require.Len(t, events, 1)
		assert.IsType(t, goauth2.UserWasOnBoarded{}, events[0])
	})
}

type eventRecorder struct {
	Records []*rangedb.Record
}

func (e *eventRecorder) Accept(record *rangedb.Record) {
	e.Records = append(e.Records, record)
}
