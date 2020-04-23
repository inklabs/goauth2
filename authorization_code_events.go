package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id AuthorizationCode -methodName EventType -aggregateType authorization-code -inFile authorization_code_events.go -outFile authorization_code_events_gen.go

// RequestAccessTokenViaAuthorizationCodeGrant events
type AuthorizationCodeWasIssuedToUser struct {
	AuthorizationCode string `json:"authorizationCode"`
	UserID            string `json:"userID"`
	ClientID          string `json:"clientID"`
	ExpiresAt         int64  `json:"expiresAt"`
	Scope             string `json:"scope"`
}
type AccessTokenWasIssuedToUserViaAuthorizationCodeGrant struct {
	AuthorizationCode string `json:"authorizationCode"`
	UserID            string `json:"userID"`
	ClientID          string `json:"clientID"`
}
type RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
	UserID            string `json:"userID"`
	RefreshToken      string `json:"refreshToken"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationSecret struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
	RedirectURI       string `json:"redirectURI"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidAuthorizationCode struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToExpiredAuthorizationCode struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToPreviouslyUsedAuthorizationCode struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
}
