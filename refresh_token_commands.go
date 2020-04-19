package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id RefreshToken -methodName CommandType -aggregateType refresh-token -inFile refresh_token_commands.go -outFile refresh_token_commands_gen.go

type RequestAccessTokenViaRefreshTokenGrant struct {
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	Scope        string `json:"scope"`
}
type IssueRefreshTokenToUser struct {
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userID"`
	ClientID     string `json:"clientID"`
	Scope        string `json:"scope"`
}
