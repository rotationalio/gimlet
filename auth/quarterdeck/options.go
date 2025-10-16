package quarterdeck

import (
	"net/http"
	"net/url"
)

type Option func(*Quarterdeck) error

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

func NoSync() Option {
	return func(q *Quarterdeck) error {
		q.syncInit = false
		return nil
	}
}

func NoRun() Option {
	return func(q *Quarterdeck) error {
		q.runInit = false
		return nil
	}
}
