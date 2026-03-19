# Gimlet [![Go Reference](https://pkg.go.dev/badge/go.rtnl.ai/gimlet.svg)](https://pkg.go.dev/go.rtnl.ai/gimlet)

**Middleware for server applications that use the Gin web framework**

## Usage

Add gimlet to your server application that uses the [Gin web framework](https://gin-gonic.com/) as follows:

```
go get go.rtnl.ai/gimlet
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

## Logging

Our logging middleware uses [`log/slog`](https://pkg.go.dev/log/slog) instead of the default http logger. It has several helpers to combine logs into a JSON output that can be read by different log tools.

To use the middleware, add your service name and semantic version to each log message:

```go
router.Use(logger.Logger("myservice", "1.1.0"))
```

The logger handles errors using the `c.Errors` construct. If there is 1 error, then it is included as a single error attribute, otherwise all errors are included as an errors array. For example:

```go
func MyHandler(c *gin.Context) {
    c.Error(errors.New("something bad happened"))
    c.JSON(http.StatusBadRequest, gin.H{"error": "could not complete request"})
}
```

Will ensure that "something bad happened" is logged with the errors. Note that 400 errors are logged at warn level, 500 errors are logged at error level and all others are logged at info level.

If you would like to add logs related to a specific request, using the `Tracing` functionality. This will ensure the request ID for all log messages is shared so that you can track a single request across multiple log messages.

```go
func MyHandler(c *gin.Context) {
    log := logger.Tracing(c)
    log.InfoContext(c.Request.Context(), "something happened during this request")
}
```

**IMPORTANT: When a context is available, prefer context-aware slog APIs (for example, `slog.InfoContext()` instead of `slog.Info()`) so trace and log correlation is preserved.**

NOTE: this package also provides configuration handlers for decoding log levels with `confire`. Most log configuration looks like:

```go
type Config struct {
    LogLevel     logger.LevelDecoder `split_words:"true" default:"info" desc:"specify the verbosity of logging (trace, debug, info, warn, error, fatal panic)"`
    ConsoleLog   bool                `split_words:"true" default:"false" desc:"if true logs colorized human readable output instead of json"`
}

func (c Config) GetLogLevel() slog.Level {
    return c.LogLevel.Level()
}
```

And then slog is configured via:

```go
func NewServer(conf config.Config) {
    ...

    // Configure global level and optional console output
    opts := &slog.HandlerOptions{Level: conf.GetLogLevel()}
    h := slog.NewJSONHandler(os.Stdout, opts)
    if conf.ConsoleLog {
        h = slog.NewTextHandler(os.Stdout, opts)
    }
    slog.SetDefault(slog.New(h))

    ...
}
```

## OpenTelemetry (Observability - o11y)

Gimlet has middleware to provide spans to the context of a gin request so that a request can be traced across processes and metrics can be computed and collected by OpenTelemetry collectors for observability and debugging.

You can quickly and easily get started with the `o11y` middleware as follows:

```go
router.Use(o11y.Middleware("myservice"))
```

The middleware sets up a tracer and meter provider and also sets up an HTTP server specific meter to record HTTP request and response metrics by default.

The middleware ensures the tracer is set on the gin context (and the golang context) and ensures that any propagation from previous services is carred forward. At the end of the request the metrics are recorded.

Inside of a gin handler func, you can create a child span to start recording attributes or events as follows:

```go
func UserDetail(c *gin.Context) {
    _, span := tracer.Start(
        c.Request.Context(), "userDetail",
    )
    defer span.End()

    if user, err := db.GetUser(c.Param("id")); err != nil {
        c.Error(err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve user"})
        return
    }
    span.SetAttributes(attribute.Key("userID").String(user.ID))
}
```

**NOTE**: You do not have to record errors on the span unless you with to record them on the child span. Any error logged by `c.Error()` will be recorded on the request span and the span's status will be set to Error.

You can fully customize the behavior of the o11y middleware using `Option` functions passed to the `o11y.Middleware` function. The most notable are the `Filter` and `GinFilter` functions, which allow you to skip tracing of specific requests. This is particularly useful for kubernetes probes or status endpoints. For example:

```go
func FilterProbes(r *http.Request) bool {
    switch r.URL.Path {
    case "/readyz", "/livez", "healthz":
        return false
    default:
        return true
    }
}

func FilterStatus(c *gin.Context) bool {
    if c.FullPath() == "/v1/status" {
        return false
    }
    return true
}

router.Use(
    o11y.Middleware("
        myservice",
        o11y.WithFilter(FilterProbes),
        o11y.WithGinFilter(FilterStatus)
    )
)
```

## Quarterdeck & JWT Tokens

Gimlet provides middleware to authenticate with our proxy authentication service, Quarterdeck. Quarterdeck issues JWT access and refresh tokens that the gimlet middleware uses to ensure a user's claims were issued by the Quarterdeck server and to check if the claims have the permissions to perform a specific action.

### Authentication

You'll need a Quarterdeck configuration URL to get started; usually something like `https://auth.rotational.app/.well-known/openid-configuration` -- you can then instantiate the quarterdeck middleware as follows:

```go
const (
    quarterdeckURL = "https://auth.rotational.app/.well-known/openid-configuration"
    audience = "https://myapp.com"
)

qd, err := quarterdeck.New(quarterdeckURL, audience)
auth, err := auth.Authenticate(qd)
```

You can now use the `Login` or `Authenticate` endpoints of Quarterdeck to set authentication cookies or to get an access token to put into the `Authorization` header as a bearer token and this middleware will validate those tokens before allowing the request to be handled further or returns a 401 not authorized error.

The authentication middleware will add the claims to the gin context for handlers to get access to. To fetch the claims use:

```go
func MyRoute(c *gin.Context) {
    claims, err := auth.GetClaims(c)
}
```

### Authorization

Authorization checks to make sure the claims have all permissions specified when setting up the middleware. For example, a rest endpoint might be set up as follows:

```go
tasks := router.Group("/tasks", authenticate)
{
    tasks.GET("/", auth.Authorize("tasks:read"), ListTasks)
    tasks.POST("/", auth.Authorize("tasks:write"), CreateTask)
    tasks.GET("/:id", auth.Authorize("tasks:read"), TaskDetail)
    tasks.PUT("/:id", auth.Authorize("tasks:write"), UpdateTask)
    tasks.DELETE("/:id", auth.Authorize("tasks:write", "tasks:delete"), DeleteTask)
}
```

Note that the authentication middleware must be added before any authorize handlers are added to specific routes (to ensure claims are on the context).

If the permission specified isn't in the Permissions of the claims, then a 401 not authorized error is returned.

### Claims

The `auth.Authenticate` middleware sets the claims on the request so that you can use the claims elsewhere in your service handler. To get the authentication claims:

```go
func MyHandler(c *gin.Context) {
    claims, err := auth.GetClaims(c)
}
```

The claims will be of type `*auth.Claims` which have the standard rotational claims attached. If you need a generic type of claims that you will type check yourself:

```go
func MyHandler(c *gin.Context) {
    // Use whichever key the custom claims were saved on.
    claims, exists := gimlet.Get(c, gimlet.KeyUserClaims)
}
```

### Testing

You can use the `authtest` package to write tests against the Authentication middleware without mocking or bypassing the middleware.

```go
func TestMyRoute(t *testing.T) {
    srv := authtest.New() // will automatically cleanup the server when the test is complete
    client := srv.Client()

    qd, err := quarterdeck.New(srv.ConfigURL, authtest.Audience,
        quarterdeck.WithClient(client),
        quarterdeck.WithIssuer(authtest.Issuer),
    )
    require.NoError(t, err, "could not setup quarterdeck server")

    auth, err := auth.Authenticate(qd)
    require.NoError(t, err, "could not setup authenticate middleware")

    router.GET("/", auth, MyRoute)

    // Create an access token
    claims := &auth.Claims{
        Name: "Test User",
        Email: "test@example.com",
        Permissions: ["foo:read", "foo:write"],
    }
    claims.SetSubjectID(auth.SubjectUser, ulid.Make())

    accessToken, err := srv.CreateAccessToken(claims)
    require.NoError(t, err, "could not create access token")

    // Create a new request.
    req, _ := http.NewRequest(http.MethodGet, "/", nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)
}
```

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
    router := gin.New()
    router.GET("/myform", s.GetForm)
    router.POST("/myform", csrf.DoubleCookie(s.csrf), s.PostForm)
}
```

Implement `csrf.TokenHandler` to create your own double cookie generator and verifier.

## Cache Control

The `cache.Control` middleware manages request and response headers for cache control by providing the user an interface to set ETags, LastModified, Expires, and Cache Control directives on objects managed by the middleware. The middleware itself will respond correctly to `If-None-Match`, `If-Last-Modified`, and `If-Unmodified-Since` requests and will set the `Last-Modified`, `Expires`, `ETag`, and `Cache-Control` headers on the outgoing response.

To manage a single object, create a new cache control manager as follows:

```go
cached := router.Group("/myobj", cache.Control(cache.New("must-revalidate, private")))
{
    cached.GET("/", GetObj)
    cached.PUT("/", PutObj)
}

func GetObj(c *gin.Context) {
    c.JSON(http.StatusOk, myobj)
}

func PutObj(c *gin.Context) {
    // Set last modified timestamp and max age duration
    cache.Modified(time.Now(), 8*time.Hour)

    // Compute the ETag from the data
    data, _ := json.Marshal(myobj)
    cache.ComputeETag(data)

    c.JSON(http.StatusOk, gin.H{"success": true})
}
```

If you would like to manage multiple objects, with the same handler using a map, please open an GitHub issue and let us know that would be useful to you!

Note that the `cache.Control` takes a handler that can be very flexible. See the `ETagger`, `Expirer`, and `CacheController` interfaces for adding your own cache handlers to the middleware. Additionally there are built-in controllers such as `Manager`, `ETag`, `WeakETag`, `Expires`, and `CacheControl` that can give you more fine grained control of the cache settings.

## Secure

The secure middleware provides several security enhancements to response handling and ensures that modern browser directive headers are included in the response. The middleware can be configured to determine how headers and responses are handled.

Basic Usage:

```go
config := &secure.Config{
    ContentTypeNosniff: true,
    CrossOriginOpenerPolicy: secure.SameOrigin,
    ReferrerPolicy: secure.StrictOriginWhenCrossOrigin,
    HSTS: secure.HSTSConfig{
        Seconds: 63072000,
        IncludeSubdomains: true,
        Preload: true,
    }
}

router.Use(secure.Secure(config))
```

## About

Rotational's web services built in Go use common middleware for logging, authentication, authorization, csrf protection and more. This package unifies our middleware usage across all of our web services, simplifying service development. Rotational services primarily depend on Gin as the base framework, hence gimlet - lime and gin!
