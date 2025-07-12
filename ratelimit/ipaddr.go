package ratelimit

import "github.com/gin-gonic/gin"

type ClientIP struct {
	conf Config
}

func (r *ClientIP) Allow(c *gin.Context) (bool, Headers) {
	return true, Headers{}
}

func (r *ClientIP) Cleanup() {}
