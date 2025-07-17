package auth

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"go.rtnl.ai/gimlet"
	"go.rtnl.ai/gimlet/logger"
)

const (
	authorization      = "Authorization"
	AccessTokenCookie  = "access_token"
	RefreshTokenCookie = "refresh_token"
)

var (
	ErrInvalidAuthToken = errors.New("invalid authorization token")
	ErrAuthRequired     = errors.New("this endpoint requires authentication")
	ErrParseBearer      = errors.New("could not parse Bearer token from Authorization header")
	ErrNoRefreshToken   = errors.New("no refresh token available on request")
	ErrRefreshDisabled  = errors.New("reauthentication with refresh tokens disabled")
)

type Authenticator interface {
	Verify(accessToken string) (*Claims, error)
}

func Authenticate(auth Authenticator) (_ gin.HandlerFunc, err error) {
	return func(c *gin.Context) {
		var (
			err         error
			accessToken string
			claims      *Claims
		)

		// Get the access token from the request, either from the header or cookies.
		if accessToken, err = GetAccessToken(c); err != nil {
			// TODO: attempt to reauthenticate if the access token is missing.
			log := logger.Tracing(c)
			log.Debug().Err(err).Msg("could not retrieve access token")
			gimlet.Abort(c, http.StatusUnauthorized, ErrAuthRequired)
			return
		}

		// Verify the access token is authorized for use and extract claims.
		if claims, err = auth.Verify(accessToken); err != nil {
			// TODO: attempt to reauthenticate if the access token is expired.
			log := logger.Tracing(c)
			log.Debug().Err(err).Msg("could not verify access token")
			gimlet.Abort(c, http.StatusUnauthorized, ErrAuthRequired)
			return
		}

		// Add claims to context for use in downstream handlers.
		gimlet.Set(c, gimlet.KeyUserClaims, claims)
		gimlet.Set(c, gimlet.KeyAccessToken, accessToken)

		c.Next()
	}, nil
}

// Used to extract the access token from the header
var (
	bearer = regexp.MustCompile(`^\s*[Bb]earer\s+([a-zA-Z0-9_\-\.]+)\s*$`)
)

// GetAccessToken retrieves the bearer token from the authorization header and parses it
// to return only the JWT access token component of the header. Alternatively, if the
// authorization header is not present, then the token is fetched from cookies. If the
// header is missing or the token is not available, an error is returned.
//
// NOTE: the authorization header takes precedence over access tokens in cookies.
func GetAccessToken(c *gin.Context) (tks string, err error) {
	// Attempt to get the access token from the header.
	if header := c.GetHeader(authorization); header != "" {
		match := bearer.FindStringSubmatch(header)
		if len(match) == 2 {
			return match[1], nil
		}
		return "", ErrParseBearer
	}

	// Attempt to get the access token from cookies.
	var cookie string
	if cookie, err = c.Cookie(AccessTokenCookie); err == nil {
		// If the error is nil, that means we were able to retrieve the access token cookie
		return cookie, nil
	}
	return "", ErrNoAuthorization
}

// GetRefreshToken retrieves the refresh token from the cookies in the request. If the
// cookie is not present or expired then an error is returned.
func GetRefreshToken(c *gin.Context) (tks string, err error) {
	if tks, err = c.Cookie(RefreshTokenCookie); err != nil {
		return "", ErrNoRefreshToken
	}
	return tks, nil
}

// SetAuthCookies is a helper function to set authentication cookies on a gin request.
// The access token cookie (access_token) is an http only cookie that expires when the
// access token expires. The refresh token cookie is not an http only cookie (it can be
// accessed by client-side scripts) and it expires when the refresh token expires. Both
// cookies require https and will not be set (silently) over http connections.
func SetAuthCookies(c *gin.Context, accessToken, refreshToken string, domains ...string) (err error) {
	// Parse access token to get expiration time
	var accessMaxAge int
	if accessMaxAge, err = TokenMaxAge(accessToken); err != nil {
		return err
	}

	// Parse refresh token to get expiration time
	var refreshMaxAge int
	if refreshMaxAge, err = TokenMaxAge(refreshToken); err != nil {
		return err
	}

	for _, domain := range domains {
		// If the domain is localhost or ends with .local, we set secure to false
		// so that the cookies can be set over http for local development.
		secure := !gimlet.IsLocalhost(domain)

		// Set the access token cookie: httpOnly is true; cannot be accessed by Javascript
		c.SetCookie(AccessTokenCookie, accessToken, accessMaxAge, "/", domain, secure, true)

		// Set the refresh token cookie: httpOnly is false; can be accessed by Javascript
		c.SetCookie(RefreshTokenCookie, refreshToken, refreshMaxAge, "/", domain, secure, false)
	}
	return nil
}

// ClearAuthCookies is a helper function to clear authentication cookies on a gin
// request to effectively log out a user.
func ClearAuthCookies(c *gin.Context, domains ...string) (err error) {
	for _, domain := range domains {
		secure := !gimlet.IsLocalhost(domain)
		c.SetCookie(AccessTokenCookie, "", -1, "/", domain, secure, true)
		c.SetCookie(RefreshTokenCookie, "", -1, "/", domain, secure, false)
	}
	return nil
}

// Compute the maximum age of a cookie from the access token expiration time.
func TokenMaxAge(token string) (_ int, err error) {
	var expiresAt time.Time
	if expiresAt, err = ExpiresAt(token); err != nil {
		return 0, err
	}
	return int(time.Until(expiresAt).Seconds()), nil
}
