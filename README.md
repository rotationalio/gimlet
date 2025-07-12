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

## About

Rotational's web services built in Go use common middleware for logging, authentication, authorization, csrf protection and more. This package unifies our middleware usage across all of our web services, simplifying service development. Rotational services primarily depend on Gin as the base framework, hence gimlet - lime and gin!