package traefikcloudflarejwt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const AccessHeaderName = "CF-Access-Jwt-Assertion"

type Config struct {
	TeamDomain string `json:"team_domain,omitempty"`
	PolicyAUD  string `json:"policy_aud,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TeamDomain: "",
		PolicyAUD:  "",
	}
}

type TraefikCloudflareJWT struct {
	teamDomain string
	policyAUD  string
	oidcConfig *oidc.Config
	verifier   *oidc.IDTokenVerifier
	next       http.Handler
	name       string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("no config provided")
	}
	if config.TeamDomain == "" {
		return nil, fmt.Errorf("team_domain is required")
	}

	if config.PolicyAUD == "" {
		return nil, fmt.Errorf("policy_aud is required")
	}

	teamDomain := fmt.Sprintf("https://%s.cloudflareaccess.com", config.TeamDomain)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)
	oidcConfig := &oidc.Config{
		ClientID: config.PolicyAUD,
	}
	keySet := oidc.NewRemoteKeySet(ctx, certsURL)

	verifier := oidc.NewVerifier(teamDomain, keySet, oidcConfig)

	return &TraefikCloudflareJWT{
		teamDomain: config.TeamDomain,
		policyAUD:  config.PolicyAUD,
		name:       name,
		oidcConfig: oidcConfig,
		verifier:   verifier,
		next:       next,
	}, nil
}

func (t *TraefikCloudflareJWT) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	accessJWT := req.Header.Get(AccessHeaderName)
	if accessJWT == "" {
		http.Error(rw, "CF-Access-Jwt-Assertion header is required", http.StatusUnauthorized)
		return
	}
	token, err := t.verifier.Verify(req.Context(), accessJWT)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Invalid token: %s", err.Error()), http.StatusForbidden)
		return
	}

	if token == nil {
		http.Error(rw, "token is nil", http.StatusForbidden)
		return
	}

	if !strings.HasSuffix(token.Issuer, t.teamDomain) {
		http.Error(rw, fmt.Sprintf("invalid issuer: %s", token.Issuer), http.StatusForbidden)
		return
	}

	t.next.ServeHTTP(rw, req)
}
