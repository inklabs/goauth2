package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id UserID -methodName EventType -aggregateType resource-owner -inFile resource_owner_events.go -outFile resource_owner_events_gen.go

// User Flow
type UserWasOnBoarded struct {
	UserID       string `json:"userID"`
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}
type OnBoardUserWasRejectedDueToExistingUser struct {
	UserID string `json:"userID"`
}
type OnBoardUserWasRejectedDueToInsecurePassword struct {
	UserID string `json:"userID"`
}
