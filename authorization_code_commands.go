package goauth2

//go:generate go run github.com/inklabs/rangedb/gen/commandgenerator -id AuthorizationCode -aggregateType authorization-code

type RequestAccessTokenViaAuthorizationCodeGrant struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
	ClientSecret      string `json:"clientSecret"`
	RedirectURI       string `json:"redirectURI"`
}
type IssueAuthorizationCodeToUser struct {
	AuthorizationCode string `json:"authorizationCode"`
	UserID            string `json:"userID"`
	ClientID          string `json:"clientID"`
	ExpiresAt         int64  `json:"expiresAt"`
	Scope             string `json:"scope"`
}
