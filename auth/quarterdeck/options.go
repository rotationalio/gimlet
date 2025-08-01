package quarterdeck

import "net/http"

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
