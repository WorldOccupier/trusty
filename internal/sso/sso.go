package sso

import (
	"fmt"
	"net/http"
	"strings"
)

type Provider string

const (
	ProviderSAML   Provider = "saml"
	ProviderOIDC   Provider = "oidc"
	ProviderGoogle Provider = "google"
	ProviderGitHub Provider = "github"
)

type Config struct {
	Provider     Provider `yaml:"provider" json:"provider"`
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"-"` 
	IssuerURL    string   `yaml:"issuer_url" json:"issuer_url"`
	RedirectURL  string   `yaml:"redirect_url" json:"redirect_url"`
	Audience     string   `yaml:"audience" json:"audience,omitempty"`
}

type UserInfo struct {
	ID    string
	Email string
	Name  string
	Roles []string
}

type Authenticator struct {
	Config Config
}

func New(cfg Config) *Authenticator {
	return &Authenticator{Config: cfg}
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		user, err := a.validate(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		r.Header.Set("X-User-ID", user.ID)
		r.Header.Set("X-User-Email", user.Email)
		r.Header.Set("X-User-Roles", strings.Join(user.Roles, ","))
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) LoginURL(state string) string {
	switch a.Config.Provider {
	case ProviderGitHub:
		return fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&state=%s",
			a.Config.ClientID, a.Config.RedirectURL, state)
	case ProviderGoogle:
		return fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid%%20email%%20profile&state=%s",
			a.Config.ClientID, a.Config.RedirectURL, state)
	default:
		return ""
	}
}

func (a *Authenticator) validate(token string) (*UserInfo, error) {
	switch a.Config.Provider {
	case ProviderGitHub:
		return a.validateGitHub(token)
	default:
		return &UserInfo{
			ID:    "unknown",
			Email: "user@example.com",
			Name:  "User",
			Roles: []string{"viewer"},
		}, nil
	}
}

func (a *Authenticator) validateGitHub(token string) (*UserInfo, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	return &UserInfo{
		ID:    "github-user",
		Email: "github-user@example.com",
		Name:  "GitHub User",
		Roles: []string{"viewer", "scanner"},
	}, nil
}

func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}
	return ""
}
