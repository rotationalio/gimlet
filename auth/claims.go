package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"go.rtnl.ai/ulid"
)

// These claims represent Quarterdeck specific claims used in authentication. Right now,
// they're the only claims used in Gimlet, but it is tightly coupled to Quarterdeck's
// implementation. Changes to Quarterdeck must be reflected here.
// TODO: make claims more generic so that Gimlet can be used with other services.
type Claims struct {
	jwt.RegisteredClaims
	ClientID    string   `json:"clientID,omitempty"`    // Only used for API keys, not users.
	Name        string   `json:"name,omitempty"`        // Only used for users, not API keys.
	Email       string   `json:"email,omitempty"`       // Only used for users, not API keys.
	Gravatar    string   `json:"gravatar,omitempty"`    // Only used for users, not API keys.
	Roles       []string `json:"roles,omitempty"`       // The roles assigned to a user (not used with API keys).
	Permissions []string `json:"permissions,omitempty"` // The permissions assigned to the claims.
}

func (c Claims) SubjectID() (SubjectType, ulid.ULID, error) {
	sub := SubjectType(c.Subject[0])
	id, err := ulid.Parse(c.Subject[1:])
	return sub, id, err
}

func (c Claims) SubjectType() SubjectType {
	return SubjectType(c.Subject[0])
}

func (c Claims) HasPermission(required string) bool {
	for _, permission := range c.Permissions {
		if permission == required {
			return true
		}
	}
	return false
}

func (c Claims) HasAllPermissions(required ...string) bool {
	if len(required) == 0 {
		return false
	}

	for _, perm := range required {
		if !c.HasPermission(perm) {
			return false
		}
	}
	return true
}

// ===========================================================================
// SubjectType
// ===========================================================================

// SubjectType describes what kind of claims are represented.
type SubjectType rune

const (
	SubjectUser   = SubjectType('u') // User subject type.
	SubjectAPIKey = SubjectType('k') // API key subject type.
	SubjectVero   = SubjectType('v') // Used for Vero (e.g. password reset, email verification).
)

func (s SubjectType) String() string {
	switch s {
	case SubjectUser:
		return "user"
	case SubjectAPIKey:
		return "apikey"
	case SubjectVero:
		return "vero"
	default:
		return "unknown"
	}
}
