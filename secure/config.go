package secure

import (
	"errors"
	"fmt"
	"strings"
)

type Config struct {
	ContentTypeNosniff      bool       `split_words:"true" default:"true" desc:"If true, adds the X-Content-Type-Options header with the nosniff directive."`
	CrossOriginOpenerPolicy string     `split_words:"true" default:"same-origin" desc:"Value for the Cross-Origin-Opener-Policy header."`
	ReferrerPolicy          string     `split_words:"true" default:"strict-origin-when-cross-origin" desc:"Value for the Referrer-Policy header."`
	HSTS                    HSTSConfig `split_words:"true"`
}

// HSTSConfig defines the configuration for HTTP Strict Transport Security header
type HSTSConfig struct {
	// The time, in seconds, that the browser should remember that a host is only to be
	// accessed using HTTPS. If non-zero, the HSTS directive header is added to responses.
	Seconds int `default:"0" desc:"If non-zero, the HSTS directive header is added to responses. The time, in seconds, that the browser should remember that a host is only to be accessed using HTTPS."`

	// If true adds the includeSubdomains directive to the HSTS header. It has no effect
	// unless Seconds is set to a non-zero value.
	IncludeSubdomains bool `split_words:"true" default:"false" desc:"If true adds the includeSubdomains directive to the HSTS header. It has no effect unless Seconds is set to a non-zero value."`

	// If true adds the preload directive to the HSTS header. It has no effect
	// unless Seconds is set to a non-zero value.
	Preload bool `default:"false" desc:"If true, adds the preload directive to the HSTS header. It has no effect unless Seconds is set to a non-zero value and IncludeSubdomains is true."`
}

func (c Config) Validate() (err error) {
	if _, perr := ReferrerPolicy(c.ReferrerPolicy); perr != nil {
		err = errors.Join(err, perr)
	}

	if _, perr := OpenerPolicy(c.CrossOriginOpenerPolicy); perr != nil {
		err = errors.Join(err, perr)
	}

	return err
}

func (c *Config) SetDefaults() {
	if c.ReferrerPolicy == "" {
		c.ReferrerPolicy = StrictOriginWhenCrossOrigin
	}

	if c.CrossOriginOpenerPolicy == "" {
		c.CrossOriginOpenerPolicy = SameOrigin
	}
}

func (c HSTSConfig) Directive() string {
	if c.Seconds <= 0 {
		return ""
	}

	sb := new(strings.Builder)
	fmt.Fprintf(sb, "max-age=%d", c.Seconds)

	if c.IncludeSubdomains {
		sb.WriteString("; includeSubDomains")

		if c.Preload {
			sb.WriteString("; preload")
		}
	}
	return sb.String()
}
