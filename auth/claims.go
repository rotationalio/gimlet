package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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

func (c *Claims) SetSubjectID(sub SubjectType, id ulid.ULID) {
	c.Subject = fmt.Sprintf("%c%s", sub, id)
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

//===========================================================================
// Tokens are used when reauthenticating users.
//===========================================================================

type Tokens struct {
	Context      *gin.Context // The request context that initiated the reauthentication.
	AccessToken  string       // The original access token (expired or near expiry).
	RefreshToken string       // The original refresh token (used to get new tokens, not expired).
}

type RefreshedTokens struct {
	AccessToken  string         // The new access token.
	RefreshToken string         // The new refresh token.
	Claims       *Claims        // The claims extracted from the access token.
	Cookies      []*http.Cookie // Any cookies from a reauthentication request will be set on the outgoing response.
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

//===========================================================================
// JWT Unverified Timestamp Extraction
//===========================================================================

// Used to extract expiration and not before timestamps without having to use public keys
var tsparser = jwt.NewParser(jwt.WithoutClaimsValidation())

func ParseUnverified(tks string) (claims *jwt.RegisteredClaims, err error) {
	claims = &jwt.RegisteredClaims{}
	if _, _, err = tsparser.ParseUnverified(tks, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func ExpiresAt(tks string) (_ time.Time, err error) {
	var claims *jwt.RegisteredClaims
	if claims, err = ParseUnverified(tks); err != nil {
		return time.Time{}, err
	}
	return claims.ExpiresAt.Time, nil
}

func NotBefore(tks string) (_ time.Time, err error) {
	var claims *jwt.RegisteredClaims
	if claims, err = ParseUnverified(tks); err != nil {
		return time.Time{}, err
	}
	return claims.NotBefore.Time, nil
}
