package cache

import (
	"time"

	"go.rtnl.ai/x/httpcc"
)

// Manager implements the ETagger, Expirer, and CacheController interfaces for managing
// cache control directives. It is safe for concurrent use by multiple goroutines.
type Manager struct {
	etag    ETag
	expirer Expires
	cc      CacheControl
}

// New returns a new single object cache manager with an empty response builder.
func New(directives string) *Manager {
	manager := &Manager{}
	manager.SetDirectives(directives)
	return manager
}

var _ ETagger = (*Manager)(nil)
var _ Expirer = (*Manager)(nil)
var _ CacheController = (*Manager)(nil)

func (m *Manager) SetDirectives(directives string) {
	if directives != "" {
		if rep, err := httpcc.ParseResponse(directives); err == nil {
			b := httpcc.ResponseBuilder{
				NoCache:         rep.NoCache(),
				NoStore:         rep.NoStore(),
				NoTransform:     rep.NoTransform(),
				MustRevalidate:  rep.MustRevalidate(),
				ProxyRevalidate: rep.ProxyRevalidate(),
				MustUnderstand:  rep.MustUnderstand(),
				Private:         rep.Private(),
				Public:          rep.Public(),
				Immutable:       rep.Immutable(),
				Extensions:      rep.Extensions(),
			}

			if maxAge, ok := rep.MaxAge(); ok {
				b.SetMaxAge(maxAge)
			}

			if sMaxAge, ok := rep.SMaxAge(); ok {
				b.SetSMaxAge(sMaxAge)
			}

			b.StaleWhileRevalidate, _ = rep.StaleWhileRevalidate()
			m.cc.SetDirectives(b)
		}
	}
}

func (m *Manager) ETag() string {
	return m.etag.ETag()
}

func (m *Manager) ComputeETag(data []byte) {
	m.etag.ComputeETag(data)
}

func (m *Manager) SetETag(etag string) {
	m.etag.SetETag(etag)
}

func (m *Manager) LastModified() time.Time {
	return m.expirer.LastModified()
}

func (m *Manager) Expires() time.Time {
	return m.expirer.Expires()
}

func (m *Manager) Modified(modified time.Time, durationOrExpires any) {
	m.expirer.Modified(modified, durationOrExpires)
	m.cc.SetMaxAge(durationOrExpires)
}

func (m *Manager) Directives() string {
	return m.cc.Directives()
}

// SetMaxAge is a no-op for the manager; use the Modified() method to set the max age.
func (m *Manager) SetMaxAge(maxAge any) {}

func (m *Manager) SetSMaxAge(sMaxAge any) {
	m.cc.SetSMaxAge(sMaxAge)
}
