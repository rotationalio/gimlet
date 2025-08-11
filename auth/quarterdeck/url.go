package quarterdeck

import (
	"net/url"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// LoginURL provides a thread-safe way to manage the login URL for Quarterdeck and
// tracks if the URL is set by the user (immutable) or if it is set by the OpenID
// configuration, which means it can be updated during synchronization.
type LoginURL struct {
	sync.RWMutex
	url       *url.URL
	immutable bool
}

func (l *LoginURL) Update(uri string) {
	// Do not update the URL if it is empty
	if uri == "" {
		return
	}

	l.Lock()
	defer l.Unlock()

	if l.immutable {
		return // Do not update if the URL is immutable
	}

	var err error
	if l.url, err = url.Parse(uri); err != nil {
		log.Warn().Err(err).Msg("could not parse login URL")
		l.url = nil
	}
}

func (l *LoginURL) Location(c *gin.Context) string {
	l.RLock()
	defer l.RUnlock()

	loc := *l.url
	next := c.Request.URL

	if loc.Host == next.Host {
		loc.Scheme = ""
		loc.Host = ""
		next.Scheme = ""
		next.Host = ""
	}

	var query url.Values
	if loc.RawQuery != "" {
		query, _ = url.ParseQuery(loc.RawQuery)
	} else {
		query = make(url.Values)
	}

	query.Set("next", next.String())
	loc.RawQuery = query.Encode()
	return loc.String()
}
