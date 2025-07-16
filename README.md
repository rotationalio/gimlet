# Gimlet [![Go Reference](https://pkg.go.dev/badge/go.rtnl.ai/gimlet.svg)](https://pkg.go.dev/go.rtnl.ai/gimlet)

**Middleware for server applications that use the Gin web framework**

## Usage

Add gimlet to your server application that uses the [Gin web framework](https://gin-gonic.com/) as follows:

```
$ go get go.rtnl.ai/gimlet
```

This will add the latest version of gimlet to your `go.mod` file. Middleware can be applied to all routes as follows:

```go
func main() {
    router := gin.Default()
    router.Use(gimlet.Middleware())
}
```

Or can be applied to individual routes:

```go
func main() {
    router := gin.Default()
    router.GET("/", gimlet.Middleware(), myHandler)
}
```

See the documentation about configuring and using individual middleware.

## Rate Limit

The rate limit middleware prevents abuse to a service where a DDOS or spam attack tries hundreds or thousands of requests per second. The rate limit middleware uses a token bucket approach to rate limiting: the bucket is set to a maximum of "burst" number of tokens; this is the maximum requests per second that is possible. Every second, the bucket is refreshed with a "limit" number of tokens and any request that comes into the service requires a token. If there are 0 tokens, then the request is rejected with a 429 "Too Many Requests" HTTP response.

The token bucket can become negative. E.g. if the server has a per second limit of 4 requests, and a burst of 16 requests then after a quiescent period, if the server receives 32 requests in a second, it will take 5 seconds before a request can be made again, barring any additional requests (e.g. if the client respects the 429 warning).

There are two types of rate limits:

1. Constant: rate limits all requests with the same bucket
2. ClientIP: rate limits requests on a per-IP address basis

The rate limit middleware can be created with a configuration:

```go
type Config struct {
	Type     string        `default:"constant" desc:"type of rate limiter to use; either ipaddr or constant"`
	Limit    float64       `default:"4.0" desc:"number of tokens that can be added to the ratelimit token bucket per second"`
	Burst    int           `default:"32" desc:"maximum number of tokens/requests in the ratelimit token bucket"`
	CacheTTL time.Duration `split_words:"true" default:"10m" desc:"interval at which the ratelimit token bucket is cleaned up, removing old IP addresses"`
}
```

E.g. to create a constant rate limiter you would:

```go
rate := ratelimit.RateLimit(&ratelimit.Config{Type: "constant", Limit: 64, Burst: 256})
```

Similarly, to create a per-IP rate limiter:

```go
rate := ratelimit.RateLimit(&ratelimit.Config{
    Type: "ipaddr", Limit: 4, Burst: 32, CacheTTL: 5*time.Minute
})
```

You can also pass a `ratelimit.Limiter` directly into the middleware constructor for testing purposes or to define your own rate limiter mechanism.

## CSRF Protection

[Cross-Site Request Forgeries](https://owasp.org/www-community/attacks/csrf) occur when an attacker attempts to trick a web application into executing the actions of a logged in user, generally by using social engineering to send a link via email or chat. Gimlet implements [Double Submit Cookie](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#alternative-using-a-double-submit-cookie-pattern) middleware to prevent this attack.

An endpoint that is protected by this middleware requires a request that has:

1. An HTTP CSRF reference cookie set by the server that is httpOnly
2. An X-CSRF-Token header with a token that matches the above cookie value.

The idea is that you use an endpoint (such as login or a GET request to a form) to set two cookies using a `csrf.TokenHandler` to generate and set the cookies. The cookies are a `csrf_token` that can be read by Javascript on the front-end and a `csrf_reference_token` that is http only (e.g. cannot be read by Javascript). The front-end must take the `csrf_token` value and add it to the request in the `X-CSRF-Token` header for the request to the protected endpoint to succeed.

There are two types of token handlers:

1. `csrf.NaiveCSRFTokens`: generates cryptographically random strings
2. `csrf.SignedCSRFTokens`: uses an internal secret to create an HMAC signature of the token

The Naive approach is discouraged, but is still useful. The Signed approach is much more secure as an attacker with access to the domain via another attack cannot guess the secret key and generate correct tokens.

To implement the middleware:

```go

type Server struct {
    csrf *csrf.TokenHandler
}

func (s *Server) GetForm(c *gin.Context) {
    s.csrf.SetDoubleCookieToken(c)
}

func (s *Server) PostForm(c *gin.Context) {}

func (s *Server) Serve() {
    // Generate a random secret for signed tokens
    secret := make([]byte, 0, 65)
    rand.Read(secret)

    // Create a token handler to set double cookie tokens in the GET request.
    s.csrf = csrf.NewTokenHandler(1*time.Hour, "/", []string{"example.com"}, secret)

    // Add routes one to set the token cookies, one to verify them
    handler := gin.New()
    handler.GET("/myform", s.GetForm)
    handler.POST("/myform", csrf.DoubleCookie(s.csrf), s.PostForm)
}
```

Implement `csrf.TokenHandler` to create your own double cookie generator and verifier.

## About

Rotational's web services built in Go use common middleware for logging, authentication, authorization, csrf protection and more. This package unifies our middleware usage across all of our web services, simplifying service development. Rotational services primarily depend on Gin as the base framework, hence gimlet - lime and gin!