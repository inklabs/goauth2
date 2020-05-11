package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id RefreshToken -methodName EventType -aggregateType refresh-token -inFile refresh_token_events.go -outFile refresh_token_events_gen.go

// RequestAccessTokenViaRefreshTokenGrant Events
type RefreshTokenWasIssuedToUser struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
	ClientID     string `json:"clientID"`
	Scope        string `json:"scope"`
}
type RefreshTokenWasIssuedToClientApplication struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
}
type RefreshTokenWasRevokedFromUser struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
	ClientID     string `json:"clientID"`
}
type AccessTokenWasIssuedToUserViaRefreshTokenGrant struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
	ClientID     string `json:"clientID"`
}
type AccessTokenWasIssuedToClientApplicationViaRefreshTokenGrant struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
}
type RefreshTokenWasIssuedToUserViaRefreshTokenGrant struct {
	RefreshToken     string `json:"refreshToken"`
	UserID           string `json:"userID"`
	ClientID         string `json:"clientID"`
	NextRefreshToken string `json:"nextRefreshToken"`
	Scope            string `json:"scope"`
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
type RequestAccessTokenViaRefreshTokenGrantWasRejectedDueToInvalidScope struct {
	RefreshToken   string `json:"refreshToken"`
	ClientID       string `json:"clientID"`
	Scope          string `json:"scope"`
	RequestedScope string `json:"requestedScope"`
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
	ClientID     string `json:"clientID"`
}
type AccessTokenWasRevokedDueToPreviouslyUsedRefreshToken struct {
	RefreshToken string `json:"refreshToken"`
}
