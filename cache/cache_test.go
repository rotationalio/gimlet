package cache_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.rtnl.ai/gimlet/cache"
	"go.rtnl.ai/x/httpcc"
)

func TestIntegration(t *testing.T) {
	var mu sync.RWMutex
	var message string

	router := gin.New()
	router.Use(cache.Control(cache.New("must-revalidate, private")))

	router.GET("/", func(c *gin.Context) {
		mu.RLock()
		defer mu.RUnlock()
		c.JSON(http.StatusOK, gin.H{"message": message})
	})

	router.POST("/", func(c *gin.Context) {
		mu.Lock()
		defer mu.Unlock()

		data := make(gin.H)
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		message = data["message"].(string)
		cache.ComputeETag(c, []byte(message))
		cache.Modified(c, time.Now(), 20*time.Minute)

		c.JSON(http.StatusOK, gin.H{"message": message})
	})

	srv := httptest.NewServer(router)
	defer srv.Close()

	t.Run("Empty", func(t *testing.T) {
		rep, err := http.Get(srv.URL)
		require.NoError(t, err)

		defer rep.Body.Close()
		require.Equal(t, http.StatusOK, rep.StatusCode)
		require.Equal(t, "must-revalidate, private", rep.Header.Get("Cache-Control"))
		require.Empty(t, rep.Header.Get("ETag"))
		require.Empty(t, rep.Header.Get("Expires"))
		require.Empty(t, rep.Header.Get("Last-Modified"))
	})

	t.Run("Create", func(t *testing.T) {
		rep, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"message": "Hello, World!"}`))
		require.NoError(t, err)
		rep.Body.Close()

		require.Equal(t, http.StatusOK, rep.StatusCode)
		require.Equal(t, "max-age=1200, must-revalidate, private", rep.Header.Get("Cache-Control"))
		etag := strconv.Quote(rep.Header.Get("ETag"))
		expires := rep.Header.Get("Expires")
		lastModified := rep.Header.Get("Last-Modified")

		rep, err = http.Get(srv.URL)
		require.NoError(t, err)
		rep.Body.Close()

		require.Equal(t, http.StatusOK, rep.StatusCode)
		require.Equal(t, "max-age=1200, must-revalidate, private", rep.Header.Get("Cache-Control"))
		require.Equal(t, etag, rep.Header.Get("ETag"))
		require.Equal(t, expires, rep.Header.Get("Expires"))
		require.Equal(t, lastModified, rep.Header.Get("Last-Modified"))
	})

	t.Run("IfNoneMatch", func(t *testing.T) {
		rep, err := http.Get(srv.URL)
		require.NoError(t, err)
		rep.Body.Close()

		directives, err := httpcc.Response(rep)
		require.NoError(t, err)
		etag, ok := directives.ETag()
		require.True(t, ok, "expected ETag to be present")

		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		req.Header.Set("If-None-Match", etag)

		rep, err = http.DefaultClient.Do(req)
		require.NoError(t, err)
		rep.Body.Close()

		require.Equal(t, http.StatusNotModified, rep.StatusCode)
	})

	t.Run("IfModifiedSince", func(t *testing.T) {
		rep, err := http.Get(srv.URL)
		require.NoError(t, err)
		rep.Body.Close()

		directives, err := httpcc.Response(rep)
		require.NoError(t, err)

		lastModified, ok := directives.LastModified()
		require.True(t, ok, "expected Last-Modified to be present")

		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)

		t.Run("LastModified", func(t *testing.T) {
			// Set If-Modified-Since to the last modified time
			req.Header.Set(httpcc.IfModifiedSince, lastModified.Format(http.TimeFormat))

			rep, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			rep.Body.Close()

			// It hasn't been modified since the last modified time, so we expect a 304 Not Modified
			require.Equal(t, http.StatusNotModified, rep.StatusCode)
		})

		t.Run("ModifiedAfter", func(t *testing.T) {
			// Now set If-Modified-Since to a time before the last modified time
			req.Header.Set(httpcc.IfModifiedSince, lastModified.Add(-2*time.Minute).Format(http.TimeFormat))
			rep, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			rep.Body.Close()

			// It has been modified after the if modified since time, so we expect a 200 OK
			require.Equal(t, http.StatusOK, rep.StatusCode)
		})

		t.Run("ModifiedBefore", func(t *testing.T) {
			// Set a time after the last modified time
			req.Header.Set(httpcc.IfModifiedSince, lastModified.Add(2*time.Minute).Format(http.TimeFormat))
			rep, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			rep.Body.Close()

			// It hasn't been modified since the if modified since time, so we expect a 304 Not Modified
			require.Equal(t, http.StatusNotModified, rep.StatusCode)
		})
	})

	t.Run("IfUnmodifiedSince", func(t *testing.T) {
		rep, err := http.Get(srv.URL)
		require.NoError(t, err)
		rep.Body.Close()

		directives, err := httpcc.Response(rep)
		require.NoError(t, err)

		lastModified, ok := directives.LastModified()
		require.True(t, ok, "expected Last-Modified to be present")

		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)

		t.Run("LastModified", func(t *testing.T) {
			// Set If-Unmodified-Since to the last modified time
			req.Header.Set(httpcc.IfUnmodifiedSince, lastModified.Format(http.TimeFormat))

			rep, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			rep.Body.Close()

			// It has been modified after the if unmodified since time, so we expect a 200 OK
			require.Equal(t, http.StatusOK, rep.StatusCode)
		})

		t.Run("ModifiedAfter", func(t *testing.T) {
			// Now set If-Unmodified-Since to a time before the last modified time
			req.Header.Set(httpcc.IfUnmodifiedSince, lastModified.Add(-2*time.Minute).Format(http.TimeFormat))
			rep, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			rep.Body.Close()

			// If it has been modified after the if unmodified since time, we expect a 412 Precondition Failed
			require.Equal(t, http.StatusPreconditionFailed, rep.StatusCode)
		})

		t.Run("ModifiedBefore", func(t *testing.T) {
			// Set a time after the last modified time
			req.Header.Set(httpcc.IfUnmodifiedSince, lastModified.Add(2*time.Minute).Format(http.TimeFormat))
			rep, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			rep.Body.Close()

			// It has been modified after the if modified since time, so we expect a 200 OK
			require.Equal(t, http.StatusOK, rep.StatusCode)
		})
	})
}
