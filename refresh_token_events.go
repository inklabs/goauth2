package goauth2

//go:generate go run github.com/inklabs/rangedb/gen/eventgenerator -id RefreshToken -aggregateType refresh-token

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
