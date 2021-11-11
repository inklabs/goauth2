package goauth2

import (
	"fmt"

	"github.com/inklabs/rangedb"
)

// AuthorizationCodeRefreshTokens is a projection mapping authorization codes to refresh tokens.
type AuthorizationCodeRefreshTokens struct {
	refreshTokensByAuthorizationCode map[string][]string
	authorizationCodeByRefreshToken  map[string]string
}

// NewAuthorizationCodeRefreshTokens constructs an AuthorizationCodeRefreshTokens projection.
func NewAuthorizationCodeRefreshTokens() *AuthorizationCodeRefreshTokens {
	return &AuthorizationCodeRefreshTokens{
		refreshTokensByAuthorizationCode: make(map[string][]string),
		authorizationCodeByRefreshToken:  make(map[string]string),
	}
}

// Accept receives a rangedb.Record.
func (a *AuthorizationCodeRefreshTokens) Accept(record *rangedb.Record) {
	switch event := record.Data.(type) {

	case *RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant:
		a.addRefreshToken(event.AuthorizationCode, event.RefreshToken)

	case *RefreshTokenWasIssuedToUserViaRefreshTokenGrant:
		if authorizationCode, ok := a.authorizationCodeByRefreshToken[event.RefreshToken]; ok {
			a.addRefreshToken(authorizationCode, event.NextRefreshToken)
		}

	case *RefreshTokenWasRevokedFromUser:
		if authorizationCode, ok := a.authorizationCodeByRefreshToken[event.RefreshToken]; ok {
			a.removeRefreshTokens(authorizationCode)
		}

	}
}

// GetTokens returns all refresh tokens by authorizationCode.
func (a *AuthorizationCodeRefreshTokens) GetTokens(authorizationCode string) []string {
	return a.refreshTokensByAuthorizationCode[authorizationCode]
}

// GetAuthorizationCode returns a single authorization code from a refresh token.
func (a *AuthorizationCodeRefreshTokens) GetAuthorizationCode(refreshToken string) (string, error) {
	if authorizationCode, ok := a.authorizationCodeByRefreshToken[refreshToken]; ok {
		return authorizationCode, nil
	}

	return "", ErrAuthorizationCodeNotFound
}

func (a *AuthorizationCodeRefreshTokens) addRefreshToken(authorizationCode, refreshToken string) {
	a.authorizationCodeByRefreshToken[refreshToken] = authorizationCode
	a.refreshTokensByAuthorizationCode[authorizationCode] = append(
		a.refreshTokensByAuthorizationCode[authorizationCode],
		refreshToken,
	)
}

func (a *AuthorizationCodeRefreshTokens) removeRefreshTokens(authorizationCode string) {
	for _, refreshToken := range a.refreshTokensByAuthorizationCode[authorizationCode] {
		delete(a.authorizationCodeByRefreshToken, refreshToken)
	}

	delete(a.refreshTokensByAuthorizationCode, authorizationCode)
}

// ErrAuthorizationCodeNotFound is a defined error for missing authorization code.
var ErrAuthorizationCodeNotFound = fmt.Errorf("authorization code not found")
