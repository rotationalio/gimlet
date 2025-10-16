package quarterdeck

import "time"

type OpenIDConfiguration struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEP               string   `json:"authorization_endpoint"`
	TokenEP                       string   `json:"token_endpoint"`
	DeviceAuthorizationEP         string   `json:"device_authorization_endpoint"`
	UserInfoEP                    string   `json:"userinfo_endpoint"`
	MFAChallengeEP                string   `json:"mfa_challenge_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	RegistrationEP                string   `json:"registration_endpoint"`
	RevocationEP                  string   `json:"revocation_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ResponseModesSupported        []string `json:"response_modes_supported"`
	SubjectTypesSupported         []string `json:"subject_types_supported"`
	IDTokenSigningAlgValues       []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported               []string `json:"claims_supported"`
	RequestURIParameterSupported  bool     `json:"request_uri_parameter_supported"`
}

// This struct matches the ReauthenticateRequest defined by Quarterdeck.
type TokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	Next         string `json:"next,omitempty"` // Optional redirect URL after re-authentication (not used by Gimlet)
}

// This struct matches the LoginReply response from Quarterdeck.
type TokenReply struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	LastLogin    time.Time `json:"last_login,omitempty"`
}

func (r *TokenReply) Validate() error {
	if r.AccessToken == "" {
		return ErrNoAccessToken
	}

	if r.RefreshToken == "" {
		return ErrNoRefreshToken
	}

	return nil
}
