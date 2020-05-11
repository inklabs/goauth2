package goauth2_test

import (
	"testing"

	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inklabs/goauth2"
)

func TestAuthorizationCodeRefreshTokens(t *testing.T) {
	// Given
	const (
		authorizationCode = "4da3044aa1ce4ef7a37c6a32375cf39a"
		userID            = "e2c27a06cd7c4003878979641e9e8288"
		clientID          = "17608d60710947d9803abc596184484b"
		refreshToken1     = "3afb212eef99411d91f888cf826c289f"
		refreshToken2     = "3754ba23f805431e83e0d50491311539"
		scope             = "read_write"
	)

	t.Run("authorization code is associated with one refresh token via authorization code grant", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		authorizationCodeRefreshTokens := goauth2.NewAuthorizationCodeRefreshTokens()
		store.Subscribe(authorizationCodeRefreshTokens)

		// When
		require.NoError(t, store.Save(goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			UserID:            userID,
			RefreshToken:      refreshToken1,
			Scope:             scope,
		}, nil))

		// Then
		tokens := authorizationCodeRefreshTokens.GetTokens(authorizationCode)
		assert.Equal(t, []string{refreshToken1}, tokens)
		actualAuthorizationCode, err := authorizationCodeRefreshTokens.GetAuthorizationCode(refreshToken1)
		require.NoError(t, err)
		assert.Equal(t, authorizationCode, actualAuthorizationCode)
	})

	t.Run("authorization code is associated with another refresh token via refresh token grant", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		authorizationCodeRefreshTokens := goauth2.NewAuthorizationCodeRefreshTokens()
		store.Subscribe(authorizationCodeRefreshTokens)

		// When
		require.NoError(t, store.Save(goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			UserID:            userID,
			RefreshToken:      refreshToken1,
			Scope:             scope,
		}, nil))
		require.NoError(t, store.Save(goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
			RefreshToken:     refreshToken1,
			UserID:           userID,
			ClientID:         clientID,
			NextRefreshToken: refreshToken2,
			Scope:            scope,
		}, nil))

		// Then
		assert.Equal(t, []string{refreshToken1, refreshToken2}, authorizationCodeRefreshTokens.GetTokens(authorizationCode))
		actualAuthorizationCode1, err := authorizationCodeRefreshTokens.GetAuthorizationCode(refreshToken1)
		require.NoError(t, err)
		actualAuthorizationCode2, err := authorizationCodeRefreshTokens.GetAuthorizationCode(refreshToken2)
		require.NoError(t, err)
		assert.Equal(t, authorizationCode, actualAuthorizationCode1)
		assert.Equal(t, authorizationCode, actualAuthorizationCode2)
	})

	t.Run("remove one revoked token to avoid memory leak", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		authorizationCodeRefreshTokens := goauth2.NewAuthorizationCodeRefreshTokens()
		store.Subscribe(authorizationCodeRefreshTokens)

		// When
		require.NoError(t, store.Save(goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			UserID:            userID,
			RefreshToken:      refreshToken1,
			Scope:             scope,
		}, nil))
		require.NoError(t, store.Save(goauth2.RefreshTokenWasRevokedFromUser{
			RefreshToken: refreshToken1,
			UserID:       userID,
			ClientID:     clientID,
		}, nil))

		// Then
		assert.Equal(t, []string(nil), authorizationCodeRefreshTokens.GetTokens(authorizationCode))
		actualAuthorizationCode, err := authorizationCodeRefreshTokens.GetAuthorizationCode(refreshToken1)
		assert.Equal(t, "", actualAuthorizationCode)
		assert.Equal(t, goauth2.AuthorizationCodeNotFound, err)
	})

	t.Run("remove two revoked tokens to avoid memory leak", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		authorizationCodeRefreshTokens := goauth2.NewAuthorizationCodeRefreshTokens()
		store.Subscribe(authorizationCodeRefreshTokens)

		// When
		require.NoError(t, store.Save(goauth2.RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant{
			AuthorizationCode: authorizationCode,
			ClientID:          clientID,
			UserID:            userID,
			RefreshToken:      refreshToken1,
			Scope:             scope,
		}, nil))
		require.NoError(t, store.Save(goauth2.RefreshTokenWasIssuedToUserViaRefreshTokenGrant{
			RefreshToken:     refreshToken1,
			UserID:           userID,
			ClientID:         clientID,
			NextRefreshToken: refreshToken2,
			Scope:            scope,
		}, nil))
		require.NoError(t, store.Save(goauth2.RefreshTokenWasRevokedFromUser{
			RefreshToken: refreshToken1,
			UserID:       userID,
			ClientID:     clientID,
		}, nil))
		require.NoError(t, store.Save(goauth2.RefreshTokenWasRevokedFromUser{
			RefreshToken: refreshToken2,
			UserID:       userID,
			ClientID:     clientID,
		}, nil))

		// Then
		assert.Equal(t, []string(nil), authorizationCodeRefreshTokens.GetTokens(authorizationCode))
		actualAuthorizationCode1, err := authorizationCodeRefreshTokens.GetAuthorizationCode(refreshToken1)
		assert.Equal(t, goauth2.AuthorizationCodeNotFound, err)
		actualAuthorizationCode2, err := authorizationCodeRefreshTokens.GetAuthorizationCode(refreshToken2)
		assert.Equal(t, goauth2.AuthorizationCodeNotFound, err)
		assert.Equal(t, "", actualAuthorizationCode1)
		assert.Equal(t, "", actualAuthorizationCode2)
	})

	t.Run("no events", func(t *testing.T) {
		// Given
		store := inmemorystore.New()
		goauth2.BindEvents(store)
		authorizationCodeRefreshTokens := goauth2.NewAuthorizationCodeRefreshTokens()
		store.Subscribe(authorizationCodeRefreshTokens)

		// When
		tokens := authorizationCodeRefreshTokens.GetTokens(authorizationCode)

		// Then
		assert.Equal(t, []string(nil), tokens)
		actualAuthorizationCode, err := authorizationCodeRefreshTokens.GetAuthorizationCode(refreshToken1)
		assert.Equal(t, goauth2.AuthorizationCodeNotFound, err)
		assert.Equal(t, "", actualAuthorizationCode)
	})
}
