package goauth2

//go:generate go run github.com/inklabs/rangedb/gen/commandgenerator -id RefreshToken -aggregateType refresh-token

type RequestAccessTokenViaRefreshTokenGrant struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	Scope        string `json:"scope"`
}
type IssueRefreshTokenToUser struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
	ClientID     string `json:"clientID"`
	Scope        string `json:"scope"`
}
type RevokeRefreshTokenFromUser struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
	ClientID     string `json:"clientID"`
}
