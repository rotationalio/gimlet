package gimlet

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// Abort wraps the gin context's Abort method to determine how to respond to middleware
// requests based on the Accept header. If a JSON response is expected, it sends a
// a simple JSON error response that matches other API replies in Rotational services.
// Otherwise, it simply aborts with a text response.
func Abort(c *gin.Context, code int, err any) {
	switch c.NegotiateFormat(gin.MIMEJSON, gin.MIMEHTML, gin.MIMEPlain) {
	case gin.MIMEJSON:
		c.AbortWithStatusJSON(code, Error(err))
	default:
		c.AbortWithError(code, Error(err))
	}
}

// ErrorReply is a standard error response structure used in Gimlet services.
type ErrorReply struct {
	Success bool   `json:"success"`
	Err     string `json:"error,omitempty"`
}

// Construct a new response for an error or simply return unsuccessful.
func Error(err any) ErrorReply {
	rep := ErrorReply{Success: false}
	if err == nil {
		return rep
	}

	switch err := err.(type) {
	case error:
		rep.Err = err.Error()
	case string:
		rep.Err = err
	case fmt.Stringer:
		rep.Err = err.String()
	default:
		rep.Err = "unhandled error response"
	}

	return rep
}

func (e ErrorReply) Error() string {
	return e.Err
}

func (e ErrorReply) String() string {
	return e.Err
}
