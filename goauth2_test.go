package goauth2_test

import (
	"testing"

	"github.com/inklabs/rangedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/goauth2test"
)

const (
	clientID            = "7d327d51d1304341a21c1242fcb089f4"
	clientSecret        = "c389e799ac0e4568b1c4b4c96b670605"
	redirectUri         = "https://example.com/oauth2/callback"
	wrongRedirectUri    = "https://example.com/wrong/redirect/uri"
	invalidRedirectUri  = "://invalid-uri"
	insecureRedirectUri = "http://example.com/oauth2/callback"
	userID              = "d904f8dbd4684a6591a24c8e67ea4a77"
	adminUserID         = "7dd7157576e5426ebf44e387d80f0538"
	email               = "john@example.com"
	adminEmail          = "admin@example.com"
	passwordHash        = "$2a$10$U6ej0p2d9Y8OO2635R7l/O4oEBvxgc9o6gCaQ1wjMZ77dr4qGl8nu"
	password            = "Pass123!"
	refreshToken        = "1eff35434eee448884a2d7e2dd28b119"
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
			RedirectUri:  redirectUri,
			UserID:       userID,
		}).
		Then(goauth2.ClientApplicationWasOnBoarded{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectUri:  redirectUri,
			UserID:       userID,
		}))

	t.Run("rejected due to missing user", goauth2TestCase().
		Given().
		When(goauth2.OnBoardClientApplication{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectUri:  redirectUri,
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
			RedirectUri:  redirectUri,
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
			RedirectUri:  invalidRedirectUri,
			UserID:       userID,
		}).
		Then(goauth2.OnBoardClientApplicationWasRejectedDueToInvalidRedirectUri{
			ClientID:    clientID,
			RedirectUri: invalidRedirectUri,
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
			RedirectUri:  insecureRedirectUri,
			UserID:       userID,
		}).
		Then(goauth2.OnBoardClientApplicationWasRejectedDueToInsecureRedirectUri{
			ClientID:    clientID,
			RedirectUri: insecureRedirectUri,
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
				RedirectUri:  redirectUri,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectUri: redirectUri,
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
			RedirectUri: redirectUri,
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
				RedirectUri:  redirectUri,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectUri: wrongRedirectUri,
			Username:    email,
			Password:    password,
		}).
		Then(goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationRedirectUri{
			UserID:      userID,
			ClientID:    clientID,
			RedirectUri: wrongRedirectUri,
		}))

	t.Run("rejected due to missing user", goauth2TestCase().
		Given(
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectUri:  redirectUri,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectUri: redirectUri,
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
				RedirectUri:  redirectUri,
				UserID:       adminUserID,
			}).
		When(goauth2.RequestAccessTokenViaImplicitGrant{
			UserID:      userID,
			ClientID:    clientID,
			RedirectUri: redirectUri,
			Username:    email,
			Password:    "wrong-password",
		}).
		Then(goauth2.RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUserPassword{
			UserID:   userID,
			ClientID: clientID,
		}))
}

func Test_RequestAccessTokenViaROPCGrant(t *testing.T) {
	tokenGenerator := goauth2test.NewSeededTokenGenerator(refreshToken)

	t.Run("access and refresh tokens are issued", goauth2TestCase(goauth2.WithTokenGenerator(tokenGenerator)).
		Given(
			goauth2.UserWasOnBoarded{
				UserID:       userID,
				Username:     email,
				PasswordHash: passwordHash,
			},
			goauth2.ClientApplicationWasOnBoarded{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectUri:  redirectUri,
				UserID:       adminUserID,
			},
		).
		When(goauth2.RequestAccessTokenViaROPCGrant{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Username:     email,
			Password:     password,
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
			RedirectUri:  redirectUri,
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
			RedirectUri:  redirectUri,
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
				RedirectUri:  redirectUri,
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
