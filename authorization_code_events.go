package goauth2

//go:generate go run github.com/inklabs/rangedb/gen/eventgenerator -id AuthorizationCode -aggregateType authorization-code

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
	Scope             string `json:"scope"`
	ExpiresAt         int64  `json:"expiresAt"`
}
type RefreshTokenWasIssuedToUserViaAuthorizationCodeGrant struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
	UserID            string `json:"userID"`
	RefreshToken      string `json:"refreshToken"`
	Scope             string `json:"scope"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationSecret struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
}
type RequestAccessTokenViaAuthorizationCodeGrantWasRejectedDueToUnmatchedClientApplicationID struct {
	AuthorizationCode string `json:"authorizationCode"`
	RequestedClientID string `json:"requestedClientID"`
	ActualClientID    string `json:"actualClientID"`
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
	UserID            string `json:"userID"`
}
