package goauth2

//go:generate go run github.com/inklabs/rangedb/gen/commandgenerator -id ClientID -aggregateType client-application

type OnBoardClientApplication struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`
	UserID       string `json:"userID"`
}
type RequestAccessTokenViaClientCredentialsGrant struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}
