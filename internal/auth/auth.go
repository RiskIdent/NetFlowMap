package auth

import (
	"context"
	"net/http"

	"github.com/RiskIdent/NetFlowMap/internal/config"
	"github.com/RiskIdent/NetFlowMap/internal/logging"
)

// contextKey is a type for context keys.
type contextKey string

const (
	// UserContextKey is the context key for the current user.
	UserContextKey contextKey = "user"
)

// Service provides authentication functionality.
type Service struct {
	enabled        bool
	sessionManager *SessionManager
	userStore      *UserStore
	oidcProvider   *OIDCProvider
}

// NewService creates a new authentication service.
func NewService(ctx context.Context, cfg *config.AuthConfig, useHTTPS bool) (*Service, error) {
	if !cfg.Enabled {
		logging.Info("authentication is disabled")
		return &Service{enabled: false}, nil
	}

	service := &Service{
		enabled:        true,
		sessionManager: NewSessionManager(cfg.SessionSecret, cfg.GetSessionDuration(), useHTTPS),
	}

	// Initialize local user store
	if cfg.IsLocalEnabled() {
		userStore, err := NewUserStore(cfg.GetUsersFile())
		if err != nil {
			return nil, err
		}
		service.userStore = userStore
		logging.Info("local authentication enabled", "users_file", cfg.GetUsersFile())
	}

	// Initialize OIDC provider
	if cfg.IsOIDCEnabled() {
		oidcProvider, err := NewOIDCProvider(ctx, cfg.OIDC)
		if err != nil {
			return nil, err
		}
		service.oidcProvider = oidcProvider
		logging.Info("OIDC authentication enabled", "issuer", cfg.OIDC.IssuerURL)
	}

	return service, nil
}

// IsEnabled returns whether authentication is enabled.
func (s *Service) IsEnabled() bool {
	return s.enabled
}

// HasLocalAuth returns whether local authentication is available.
func (s *Service) HasLocalAuth() bool {
	return s.userStore != nil
}

// HasOIDC returns whether OIDC authentication is available.
func (s *Service) HasOIDC() bool {
	return s.oidcProvider != nil
}

// SessionManager returns the session manager.
func (s *Service) SessionManager() *SessionManager {
	return s.sessionManager
}

// UserStore returns the user store.
func (s *Service) UserStore() *UserStore {
	return s.userStore
}

// OIDCProvider returns the OIDC provider.
func (s *Service) OIDCProvider() *OIDCProvider {
	return s.oidcProvider
}

// Close cleans up resources used by the auth service.
func (s *Service) Close() {
	if s.oidcProvider != nil {
		s.oidcProvider.Close()
	}
}

// Middleware creates an authentication middleware.
// It extracts the user from the session and adds it to the request context.
// If auth is disabled, it sets the user as admin.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var user *User

		if !s.enabled {
			// Auth disabled - treat as admin
			user = &User{
				Username: "admin",
				Role:     RoleAdmin,
			}
		} else {
			// Try to get user from session
			claims, err := s.sessionManager.GetSessionFromRequest(r)
			if err == nil {
				user = &User{
					Username: claims.Username,
					Role:     claims.Role,
				}
			} else {
				// Anonymous user
				user = &User{
					Username: "",
					Role:     RoleAnonymous,
				}
			}
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext retrieves the user from the request context.
func GetUserFromContext(ctx context.Context) *User {
	user, ok := ctx.Value(UserContextKey).(*User)
	if !ok {
		return &User{Role: RoleAnonymous}
	}
	return user
}

// RequireAuth is a middleware that requires authentication.
// Unauthenticated requests are redirected to the login page.
func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.enabled {
			next.ServeHTTP(w, r)
			return
		}

		user := GetUserFromContext(r.Context())
		if user.Role == RoleAnonymous {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireAdmin is a middleware that requires admin role.
func (s *Service) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		if user.Role != RoleAdmin {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

