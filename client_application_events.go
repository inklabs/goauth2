package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id ClientID -methodName EventType -aggregateType client-application -inFile client_application_events.go -outFile client_application_events_gen.go

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
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationID struct {
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaClientCredentialsGrantWasRejectedDueToInvalidClientApplicationSecret struct {
	ClientID string `json:"clientID"`
}
