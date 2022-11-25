package traefikcloudflarejwt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Cyb3r-Jak3/traefikcloudflarejwt/internal/verify"
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
	oidcConfig *verify.Config
	verifier   *verify.IDTokenVerifier
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

	teamDomain := fmt.Sprintf("https://%s.cloudflareaccess.com", config.TeamDomain)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)
	oidcConfig := &verify.Config{
		ClientID: config.PolicyAUD,
	}
	keySet := verify.NewRemoteKeySet(ctx, certsURL)

	verifier := verify.NewVerifier(teamDomain, keySet, oidcConfig)

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
	ctx := req.Context()
	token, err := t.verifier.Verify(ctx, accessJWT)
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
