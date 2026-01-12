package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kai/netflowmap/internal/config"
	"github.com/kai/netflowmap/internal/logging"
	"golang.org/x/oauth2"
)

const (
	// stateTTL is how long an OIDC state parameter is valid
	stateTTL = 10 * time.Minute
	// stateCleanupInterval is how often to clean up expired states
	stateCleanupInterval = 5 * time.Minute
)

// stateEntry holds a state parameter with its creation time
type stateEntry struct {
	createdAt time.Time
}

// OIDCProvider handles OpenID Connect authentication.
type OIDCProvider struct {
	mu           sync.RWMutex
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	adminUsers   map[string]bool
	states       map[string]*stateEntry // CSRF protection with TTL
	stopCleanup  chan struct{}
}

// OIDCClaims represents the claims we extract from the ID token.
type OIDCClaims struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"preferred_username"`
}

// NewOIDCProvider creates a new OIDC provider.
func NewOIDCProvider(ctx context.Context, cfg *config.OIDCConfig) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	// Build admin users map
	adminUsers := make(map[string]bool)
	for _, user := range cfg.AdminUsers {
		adminUsers[user] = true
	}

	p := &OIDCProvider{
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
		adminUsers:   adminUsers,
		states:       make(map[string]*stateEntry),
		stopCleanup:  make(chan struct{}),
	}

	// Start state cleanup goroutine
	go p.cleanupLoop()

	return p, nil
}

// Close stops the OIDC provider cleanup goroutine.
func (p *OIDCProvider) Close() {
	close(p.stopCleanup)
}

// cleanupLoop periodically removes expired state entries.
func (p *OIDCProvider) cleanupLoop() {
	ticker := time.NewTicker(stateCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCleanup:
			return
		case <-ticker.C:
			p.cleanupExpiredStates()
		}
	}
}

// cleanupExpiredStates removes state entries older than stateTTL.
func (p *OIDCProvider) cleanupExpiredStates() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	expired := 0
	for state, entry := range p.states {
		if now.Sub(entry.createdAt) > stateTTL {
			delete(p.states, state)
			expired++
		}
	}

	if expired > 0 {
		logging.Debug("cleaned up expired OIDC states", "count", expired)
	}
}

// GetAuthURL returns the URL to redirect the user to for authentication.
func (p *OIDCProvider) GetAuthURL() (string, string) {
	state := generateState()

	p.mu.Lock()
	p.states[state] = &stateEntry{createdAt: time.Now()}
	p.mu.Unlock()

	url := p.oauth2Config.AuthCodeURL(state)
	return url, state
}

// ValidateState checks if a state parameter is valid and not expired.
func (p *OIDCProvider) ValidateState(state string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, exists := p.states[state]
	if !exists {
		return false
	}

	// Remove state (single-use)
	delete(p.states, state)

	// Check if expired
	if time.Since(entry.createdAt) > stateTTL {
		logging.Debug("OIDC state expired", "age", time.Since(entry.createdAt))
		return false
	}

	return true
}

// HandleCallback processes the OIDC callback and returns user info.
func (p *OIDCProvider) HandleCallback(ctx context.Context, r *http.Request) (*User, error) {
	// Verify state
	state := r.URL.Query().Get("state")
	if !p.ValidateState(state) {
		return nil, fmt.Errorf("invalid state parameter")
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("no authorization code received")
	}

	oauth2Token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Determine username
	username := claims.Username
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Name
	}
	if username == "" {
		return nil, fmt.Errorf("no username found in claims")
	}

	// Determine role based on admin users list
	role := RoleUser
	if p.adminUsers[username] {
		role = RoleAdmin
		logging.Debug("user granted admin role via OIDC admin_users config", "username", username)
	}

	return &User{
		Username: username,
		Role:     role,
	}, nil
}

// generateState generates a random state string for CSRF protection.
func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

