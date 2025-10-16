package quarterdeck

import (
	"net/url"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// ConfigURL provides a thread-safe way to manage the login and reauthentication URLs
// for Quarterdeck and tracks if the URL is set by the user (immutable) or if it is set
// by the OpenID configuration, which means it can be updated during synchronization.
type ConfigURL struct {
	sync.RWMutex
	url       *url.URL
	immutable bool
}

func (l *ConfigURL) Update(uri string) {
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
		log.Warn().Err(err).Msg("could not parse the configuration URL")
		l.url = nil
	}
}

func (l *ConfigURL) Location(c *gin.Context) string {
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

func (l *ConfigURL) String() string {
	l.RLock()
	defer l.RUnlock()
	return l.url.String()
}
