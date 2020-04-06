package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id ClientID -methodName CommandType -aggregateType client-application -inFile client_application_commands.go -outFile client_application_commands_gen.go

type RequestAccessTokenViaClientCredentialsGrant struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}
