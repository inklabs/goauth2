package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id RefreshToken -methodName EventType -aggregateType refresh-token -inFile refresh_token_events.go -outFile refresh_token_events_gen.go

// RequestAccessTokenViaRefreshTokenGrant Events
type RefreshTokenWasIssuedToUser struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
	Username     string `json:"username"`
}
type RefreshTokenWasIssuedToClientApplication struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
}
type RefreshTokenWasRevoked struct {
	RefreshToken string `json:"refreshToken"`
}
type AccessTokenWasIssuedToUserViaRefreshTokenGrant struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
}
type AccessTokenWasIssuedToClientApplicationViaRefreshTokenGrant struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
}
type RefreshTokenWasIssuedToUserViaRefreshTokenGrant struct {
	RefreshToken     string `json:"refreshToken"`
	UserID           string `json:"userID"`
	NextRefreshToken string `json:"nextRefreshToken"`
}
type RefreshTokenWasIssuedToClientApplicationViaRefreshTokenGrant struct {
	RefreshToken     string `json:"refreshToken"`
	ClientID         string `json:"clientID"`
	NextRefreshToken string `json:"nextRefreshToken"`
}
type RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidRefreshToken struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
}
type RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidClientApplicationCredentials struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
}
type RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToPreviouslyUsedRefreshToken struct {
	RefreshToken string `json:"refreshToken"`
}
type RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToRevokedRefreshToken struct {
	RefreshToken string `json:"refreshToken"`
}
type AccessTokenWasRevokedDueToPreviouslyUsedRefreshToken struct {
	RefreshToken string `json:"refreshToken"`
}
