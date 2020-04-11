package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id AuthorizationCode -methodName CommandType -aggregateType authorization-code -inFile authorization_code_commands.go -outFile authorization_code_commands_gen.go

type RequestAccessTokenViaAuthorizationCodeGrant struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientID          string `json:"clientID"`
	ClientSecret      string `json:"clientSecret"`
	RedirectUri       string `json:"redirectUri"`
	UserID            string `json:"userID"`
}
