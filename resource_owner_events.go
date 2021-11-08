package goauth2

//go:generate go run github.com/inklabs/rangedb/gen/eventgenerator -id UserID -aggregateType resource-owner

// OnBoardUser Events
type UserWasOnBoarded struct {
	UserID         string `json:"userID"`
	Username       string `json:"username"`
	PasswordHash   string `json:"passwordHash"`
	GrantingUserID string `json:"grantingUserID"`
}
type OnBoardUserWasRejectedDueToNonAdministrator struct {
	UserID         string `json:"userID"`
	GrantingUserID string `json:"grantingUserID"`
}
type OnBoardUserWasRejectedDueToExistingUser struct {
	UserID         string `json:"userID"`
	GrantingUserID string `json:"grantingUserID"`
}
type OnBoardUserWasRejectedDueToInsecurePassword struct {
	UserID         string `json:"userID"`
	GrantingUserID string `json:"grantingUserID"`
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

// RequestAccessTokenViaImplicitGrant Events
type AccessTokenWasIssuedToUserViaImplicitGrant struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationID struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidClientApplicationRedirectURI struct {
	UserID      string `json:"userID"`
	ClientID    string `json:"clientID"`
	RedirectURI string `json:"redirectURI"`
}
type RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUser struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaImplicitGrantWasRejectedDueToInvalidUserPassword struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}

// RequestAccessTokenViaROPCGrant Events
type AccessTokenWasIssuedToUserViaROPCGrant struct {
	UserID    string `json:"userID"`
	ClientID  string `json:"clientID"`
	ExpiresAt int64  `json:"expiresAt"`
	Scope     string `json:"scope"`
}
type RefreshTokenWasIssuedToUserViaROPCGrant struct {
	UserID       string `json:"userID"`
	ClientID     string `json:"clientID"`
	RefreshToken string `json:"refreshToken"`
	Scope        string `json:"scope"`
}
type RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUser struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidUserPassword struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
type RequestAccessTokenViaROPCGrantWasRejectedDueToInvalidClientApplicationCredentials struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}

// RequestAuthorizationCodeViaAuthorizationCodeGrant Events
type AuthorizationCodeWasIssuedToUserViaAuthorizationCodeGrant struct {
	UserID            string `json:"userID"`
	ClientID          string `json:"clientID"`
	AuthorizationCode string `json:"authorizationCode"`
	ExpiresAt         int64  `json:"expiresAt"`
	Scope             string `json:"scope"`
}
type RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationID struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
type RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidClientApplicationRedirectURI struct {
	UserID      string `json:"userID"`
	ClientID    string `json:"clientID"`
	RedirectURI string `json:"redirectURI"`
}
type RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUser struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
type RequestAuthorizationCodeViaAuthorizationCodeGrantWasRejectedDueToInvalidUserPassword struct {
	UserID   string `json:"userID"`
	ClientID string `json:"clientID"`
}
