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

// Verifies that an access token is valid and returns the claims contained in the token.
type Authenticator interface {
	Verify(accessToken string) (*Claims, error)
}

// Optional interface that can be implemented by authenticators to reauthenticate the
// user if the access token is expired and a refresh token is available.
type Reauthenticator interface {
	Refresh(accessToken, refreshToken string) (*Claims, error)
}

// Optional interface that can be implemented by authenticators to provide custom
// behavior when authentication (and re-authentication) fails such as redirecting
// to a login page.
type Unauthenticator interface {
	NotAuthorized(c *gin.Context) error
}

type reauthenticatorFunc func(string, string) (*Claims, error)
type failureHandlerFunc func(*gin.Context) error

func Authenticate(auth Authenticator) (_ gin.HandlerFunc, err error) {
	// Create the inner re-authentication handler that will be used to reauthenticate
	// the user if the access token is expired and a refresh token is available.
	var reauthenticate reauthenticatorFunc
	if ra, ok := auth.(Reauthenticator); ok {
		reauthenticate = ra.Refresh
	}

	// Create the authentication handler that will be used to authenticate a request
	// from the access token in the header or in cookies; reauthenticating if necessary.
	authenticate := func(c *gin.Context) (claims *Claims, err error) {
		// Get the access token from the request, either from the header or cookies.
		var accessToken string
		if accessToken, err = GetAccessToken(c); err != nil {
			// NOTE: do not attempt to reauthenticate if the access token is not present.
			// This is because the refresh token is set and collected in a cookie
			// that can be accessed by JavaScript, so that it can be used to
			// reauthenticate via a POST request to the server. However, this makes
			// cookie based reauthentication insecure, and thus it is not handled
			// automatically by this middleware.
			log := logger.Tracing(c)
			log.Debug().Err(err).Msg("could not retrieve access token")
			return nil, ErrAuthRequired
		}

		// Verify the access token is authorized for use and extract claims.
		if claims, err = auth.Verify(accessToken); err != nil {
			log := logger.Tracing(c)
			log.Debug().Err(err).Msg("could not verify access token")

			// Attempt to reauthenticate if a reauthentication handler is available.
			if reauthenticate != nil {
				var refreshToken string
				if refreshToken, err = GetRefreshToken(c); err == nil {
					if claims, err = reauthenticate(accessToken, refreshToken); err == nil {
						// Re-authentication successful!
						gimlet.Set(c, gimlet.KeyAccessToken, accessToken)
						return claims, nil
					}
					log.Debug().Err(err).Msg("could not reauthenticate")
				}
				log.Debug().Err(err).Msg("no refresh token available for reauthentication")
			}
			return nil, ErrAuthRequired
		}

		// Authentication successful!
		gimlet.Set(c, gimlet.KeyAccessToken, accessToken)
		return claims, nil
	}

	// Create the login failure handler that will be used if authentication and
	// re-authentication both fail. By default this handler returns a 401 Unauthorized
	// and aborts the request. But handlers can also implement the LoginFailure
	// interface to provide custom behavior such as redirecting to a login page.
	var onLoginFailure failureHandlerFunc
	if olf, ok := auth.(Unauthenticator); ok {
		onLoginFailure = olf.NotAuthorized
	}

	return func(c *gin.Context) {
		var (
			err    error
			claims *Claims
		)

		if claims, err = authenticate(c); err != nil {
			if onLoginFailure != nil {
				if err = onLoginFailure(c); err != nil {
					// If the login failure handler returns an error, log it and
					// return a 401 Unauthorized as the default behavior.
					log := logger.Tracing(c)
					log.Debug().Err(err).Msg("login failure handler returned an error")
					gimlet.Abort(c, http.StatusUnauthorized, ErrAuthRequired)
					return
				}

				// Expect that onLoginFailure handled the request with the appropriate
				// response code and abort if necessary.
				return
			}

			// If there is no login failure handler, return a 401 Unauthorized with the
			// error specified by the authenticator.
			gimlet.Abort(c, http.StatusUnauthorized, err)
			return
		}

		// Authentication successful!
		// Add claims to context for use in downstream handlers.
		gimlet.Set(c, gimlet.KeyUserClaims, claims)
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

		// Set the refresh token cookie: httpOnly is false; can be accessed by JavaScript
		// So that the front-end can POST a reauthentication request to the server.
		// NOTE: this means that an access token is required to reauthenticate.
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
