package quarterdeck

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"time"

	"go.rtnl.ai/confire"
)

type Option func(*Quarterdeck) error

// SyncTimingConfig controls Quarterdeck synchronization and reauthentication timing.
type SyncTimingConfig struct {
	SyncTimeout                time.Duration `split_words:"true" default:"20s" desc:"maximum duration for each synchronization request to Quarterdeck"`
	BackoffTimeout             time.Duration `split_words:"true" default:"5m" desc:"maximum total duration allowed for synchronization retries"`
	BackoffInitialInterval     time.Duration `split_words:"true" default:"5s" desc:"initial delay between synchronization retries"`
	BackoffRandomizationFactor float64       `split_words:"true" default:"0.07" desc:"randomization factor applied to synchronization retry delays"`
	BackoffMultiplier          float64       `split_words:"true" default:"2.0" desc:"multiplier applied to the delay after each synchronization retry"`
	BackoffMaxInterval         time.Duration `split_words:"true" default:"60s" desc:"maximum delay between synchronization retries"`
	SyncInterval               time.Duration `split_words:"true" default:"1h" desc:"fallback interval when the response does not specify a cache expiry"`
	MinSyncInterval            time.Duration `split_words:"true" default:"20s" desc:"minimum delay between automatically scheduled synchronization attempts"`
	ReauthTimeout              time.Duration `split_words:"true" default:"5s" desc:"maximum duration for reauthentication requests to Quarterdeck"`
}

// NewDefaultSyncTimingConfig constructs a sync timing configuration from the confire defaults
// declared on SyncTimingConfig.
func NewDefaultSyncTimingConfig() (SyncTimingConfig, error) {
	var config SyncTimingConfig
	if err := confire.Process("quarterdeck", &config, confire.NoEnv); err != nil {
		return SyncTimingConfig{}, fmt.Errorf("could not load default Quarterdeck sync config: %w", err)
	}
	return config, nil
}

// Validate checks that all configured durations and backoff parameters are usable.
func (c SyncTimingConfig) Validate() (err error) {
	if c.SyncTimeout <= 0 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "syncTimeout", "must be positive"))
	}
	if c.BackoffTimeout <= 0 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "backoffTimeout", "must be positive"))
	}
	if c.BackoffInitialInterval <= 0 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "backoffInitialInterval", "must be positive"))
	}
	if math.IsNaN(c.BackoffRandomizationFactor) || c.BackoffRandomizationFactor < 0 || c.BackoffRandomizationFactor >= 1 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "backoffRandomizationFactor", "must be in [0, 1)"))
	}
	if math.IsNaN(c.BackoffMultiplier) || c.BackoffMultiplier <= 1 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "backoffMultiplier", "must be greater than 1"))
	}
	if c.BackoffMaxInterval < c.BackoffInitialInterval {
		err = confire.Join(err, confire.Invalid("quarterdeck", "backoffMaxInterval", "must be at least the initial interval"))
	}
	if c.SyncInterval <= 0 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "syncInterval", "must be positive"))
	}
	if c.MinSyncInterval <= 0 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "minSyncInterval", "must be positive"))
	}
	if c.ReauthTimeout <= 0 {
		err = confire.Join(err, confire.Invalid("quarterdeck", "reauthTimeout", "must be positive"))
	}
	return err
}

// WithSyncTimingConfig replaces the default timing configuration with the supplied
// config, which must contain valid values for every field. Use NewDefaultSyncTimingConfig
// to start from the package defaults and change selected values.
func WithSyncTimingConfig(config SyncTimingConfig) Option {
	return func(q *Quarterdeck) error {
		if err := config.Validate(); err != nil {
			return fmt.Errorf("invalid Quarterdeck sync timing config: %w", err)
		}
		q.syncConfig = config
		return nil
	}
}

func WithClient(client *http.Client) Option {
	return func(q *Quarterdeck) error {
		q.client = client
		return nil
	}
}

func WithIssuer(issuer string) Option {
	return func(q *Quarterdeck) error {
		q.issuer = issuer
		return nil
	}
}

func WithSigningMethods(methods []string) Option {
	return func(q *Quarterdeck) error {
		q.signingMethods = methods
		return nil
	}
}

func WithLoginURL(loginURL url.URL) Option {
	return func(q *Quarterdeck) error {
		q.loginURL = &ConfigURL{
			url:       &loginURL,
			immutable: true, // Set to true to prevent updates
		}
		return nil
	}
}

// Sets the URL used for reauthentication with Quarterdeck using a refresh token.
func WithReauthURL(reauthURL url.URL) Option {
	return func(q *Quarterdeck) error {
		q.reauthURL = &ConfigURL{
			url:       &reauthURL,
			immutable: true, // Set to true to prevent updates
		}
		return nil
	}
}

// Disable running sync once during initialization.
func NoSync() Option {
	return func(q *Quarterdeck) error {
		q.syncInit = false
		return nil
	}
}

// Disable running the sync loop upon initialization. User must call Sync and/or
// Run manually.
func NoRun() Option {
	return func(q *Quarterdeck) error {
		q.runInit = false
		return nil
	}
}
