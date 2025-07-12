package ratelimit

import "github.com/gin-gonic/gin"

type Constant struct {
	conf Config
}

func (r *Constant) Allow(c *gin.Context) (bool, Headers) {
	return true, Headers{}
}

func (r *Constant) Cleanup() {}
