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

## Logging

Our logging middleware uses [`github.com/rs/zerolog`](https://github.com/rs/zerolog) instead of the default http logger. It has several helpers to combine logs into a JSON output that can be read by different log tools.

To use the middleware, add your service name and semantic version to each log message (Note that the last `false` argument is related to Prometheus metrics, discussed in the next section):

```go
router.Use(logger.Logger("myservice", "1.1.0". false))
```

The logger handles errors using the `c.Errors` construct. If there is 1 error, then `log.With().Err(c.Errors()[0])` is used, otherwise `log.With().Errs(c.Errors())` is used. For example:

```go
func MyHandler(c *gin.Context) {
    c.Error(errors.New("something bad happened"))
    c.JSON(http.StatusBadRequest, gin{"error": "could not complete request"})
}
```

Will ensure that "something bad happened" is logged with the errrors. Note that 400 errors are `log.Warn`, 500 errors are `log.Error` and all others are `log.Info`.

If you would like to add logs related to a specific request, using the `Tracing` functionality. This will ensure the request ID for all log messages is shared so that you can track a single request across multiple log messages.

```go
func MyHandler(c *gin.Context) {
    log := logger.Tracing(c)
    log.Info().Msg("something happened during this request")
}
```

NOTE: this package also provides configuration handlers for decoding log levels with `confire` and for setting GCP levels from zerolog levels. Most log configuration looks like:

```go
type Config struct {
    LogLevel     logger.LevelDecoder `split_words:"true" default:"info" desc:"specify the verbosity of logging (trace, debug, info, warn, error, fatal panic)"`
	ConsoleLog   bool                `split_words:"true" default:"false" desc:"if true logs colorized human readable output instead of json"`
}

func (c Config) GetLogLevel() zerolog.Level {
	return zerolog.Level(c.LogLevel)
}
```

And then zerolog is configured via:

```go
func init() {
	// Initializes zerolog with our default logging requirements
	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.TimestampFieldName = logger.GCPFieldKeyTime
	zerolog.MessageFieldName = logger.GCPFieldKeyMsg

	// Add the severity hook for GCP logging
	var gcpHook logger.SeverityHook
	log.Logger = zerolog.New(os.Stdout).Hook(gcpHook).With().Timestamp().Logger()
}

func NewServer(conf config.Config) {
    ...

    // Set the global level
	zerolog.SetGlobalLevel(conf.GetLogLevel())

	// Set human readable logging if configured
	if conf.ConsoleLog {
		console := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		log.Logger = zerolog.New(console).With().Timestamp().Logger()
	}

    ...
}
```

## Prometheus Metrics

Gimlet has middleware for collecting HTTP status to expose to [Prometheus](https://prometheus.io/) metrics for observability.

You can quickly and easily get started with the `o11y` middleware as follows:

```go
metrics, err := olly.Metrics("myservice")
router.Use(metrics)
```

NOTE: this isn't the preferred way to enable metrics; if you're also using logging you should enable the metrics in the logging middleware (see below).

This method will setup the Prometheus collectors (returning an error if collectors have already beein registered) and create middleware that will track the number of requests, the response latency in seconds, and the request/response sizes in bytes. All of these metrics are disambiguated by service (as specified in the middleware constructor), HTTP method, status code, and path.

To allow Prometheus to scrape your server for these metrics, you need to add a metrics endpoint, to set this up at `GET /metrics` you can:

```go
o11y.Routes(router)
```

Or you can manually register your own route:

```go
router.GET("/mymetrics", gin.WrapH(promhttp.Handler()))
```

You should put the metrics as high up the middleware chain as possible to ensure that true latencies and response codes are logged. This is also true of the logging middleware, but you can combine both logging and metrics by enabling metrics in logging:

```go
router.Use(logger.Logger("myservice", "1.1.0". true))
```

This is the preferred way to use the middleware in production code.

### Manual use

If you want to include HTTP metrics with other custom metrics, you can use the `Setup` method to initialize and register the collectors in the package:

```go
if err = olly.Setup(); err != nil {
    return err
}
```

This method is safe to call multiple times and from multiple threads -- it will only setup the collectors once. Once they are setup you can use them directly:

```go
statusText := strconv.Itoa(status)
o11y.RequestsHandled.WithLabelValues("myservice", c.Request.Method, statusText, path).Inc()
o11y.RequestDuration.WithLabelValues("myservice", c.Request.Method, statusText, path).Observe(time.Since(started).Seconds())
o11y.RequestSize.WithLabelValues("myservice", c.Request.Method, statusText, path).Observe(float64(c.Request.ContentLength))
o11y.ResponseSize.WithLabelValues("myservice", c.Request.Method, statusText, path).Observe(float64(c.Writer.Size()))
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
    handler := gin.New()
    handler.GET("/myform", s.GetForm)
    handler.POST("/myform", csrf.DoubleCookie(s.csrf), s.PostForm)
}
```

Implement `csrf.TokenHandler` to create your own double cookie generator and verifier.

## About

Rotational's web services built in Go use common middleware for logging, authentication, authorization, csrf protection and more. This package unifies our middleware usage across all of our web services, simplifying service development. Rotational services primarily depend on Gin as the base framework, hence gimlet - lime and gin!