package goauth2

//go:generate go run github.com/inklabs/rangedb/gen/eventgenerator -id ClientID -aggregateType client-application

// OnBoardClientApplication Events

type ClientApplicationWasOnBoarded struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`
	UserID       string `json:"userID"`
}
type OnBoardClientApplicationWasRejectedDueToUnAuthorizeUser struct {
	ClientID string `json:"clientID"`
	UserID   string `json:"userID"`
}
type OnBoardClientApplicationWasRejectedDueToInsecureRedirectURI struct {
	ClientID    string `json:"clientID"`
	RedirectURI string `json:"redirectURI"`
}
type OnBoardClientApplicationWasRejectedDueToInvalidRedirectURI struct {
	ClientID    string `json:"clientID"`
	RedirectURI string `json:"redirectURI"`
}

// RequestAccessTokenViaClientCredentialsGrant Events

type AccessTokenWasIssuedToClientApplicationViaClientCredentialsGrant struct {
	ClientID  string `json:"clientID"`
	ExpiresAt int64  `json:"expiresAt"`
	Scope     string `json:"scope"`
}
type RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationID struct {
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationSecret struct {
	ClientID string `json:"clientID"`
}
