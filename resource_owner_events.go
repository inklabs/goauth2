package goauth2

//go:generate go run gen/eventgenerator/main.go -package goauth2 -id UserID -methodName EventType -aggregateType resource-owner -inFile resource_owner_events.go -outFile resource_owner_events_gen.go

// OnBoardUser Events
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

// GrantUserAdministratorRole Events
type UserWasGrantedAdministratorRole struct {
	UserID         string `json:"userID"`
	GrantingUserID string `json:"grantingUserID"`
}
type GrantUserAdministratorRoleWasRejectedDueToMissingGrantingUser struct {
	UserID         string `json:"userID"`
	GrantingUserID string `json:"grantingUserID"`
}
type GrantUserAdministratorRoleWasRejectedDueToMissingTargetUser struct {
	UserID         string `json:"userID"`
	GrantingUserID string `json:"grantingUserID"`
}
type GrantUserAdministratorRoleWasRejectedDueToNonAdministrator struct {
	UserID         string `json:"userID"`
	GrantingUserID string `json:"grantingUserID"`
}

// AuthorizeUserToOnBoardClientApplications Events
type UserWasAuthorizedToOnBoardClientApplications struct {
	UserID            string `json:"userID"`
	AuthorizingUserID string `json:"authorizingUserID"`
}
type AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingAuthorizingUser struct {
	UserID            string `json:"userID"`
	AuthorizingUserID string `json:"authorizingUserID"`
}
type AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToMissingTargetUser struct {
	UserID            string `json:"userID"`
	AuthorizingUserID string `json:"authorizingUserID"`
}
type AuthorizeUserToOnBoardClientApplicationsWasRejectedDueToNonAdministrator struct {
	UserID            string `json:"userID"`
	AuthorizingUserID string `json:"authorizingUserID"`
}
