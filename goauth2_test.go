package goauth2_test

import (
	"testing"

	"github.com/inklabs/goauth2"
)

const (
	clientID     = "7d327d51d1304341a21c1242fcb089f4"
	clientSecret = "c389e799ac0e4568b1c4b4c96b670605"
	redirectUri  = "https://example.com/oauth2/callback"
	adminUserID  = "7dd7157576e5426ebf44e387d80f0538"
)

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
