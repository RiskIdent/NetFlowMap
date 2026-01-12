package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// SessionCookieName is the name of the session cookie.
	SessionCookieName = "netflowmap_session"
)

// SessionClaims represents the JWT claims for a session.
type SessionClaims struct {
	Username string `json:"username"`
	Role     Role   `json:"role"`
	Provider string `json:"provider"` // "local" or "oidc"
	jwt.RegisteredClaims
}

// SessionManager handles session creation and validation.
type SessionManager struct {
	secret    []byte
	duration  time.Duration
	useHTTPS  bool
	rotateAt  time.Duration // Rotate token when this much time remains
}

// NewSessionManager creates a new session manager.
func NewSessionManager(secret string, duration time.Duration, useHTTPS bool) *SessionManager {
	return &SessionManager{
		secret:   []byte(secret),
		duration: duration,
		useHTTPS: useHTTPS,
		rotateAt: duration / 2, // Rotate when half the session time has passed
	}
}

// CreateSession creates a new session token for a user.
func (m *SessionManager) CreateSession(username string, role Role, provider string) (string, error) {
	now := time.Now()
	claims := SessionClaims{
		Username: username,
		Role:     role,
		Provider: provider,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.duration)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// ValidateSession validates a session token and returns the claims.
func (m *SessionManager) ValidateSession(tokenString string) (*SessionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// SetSessionCookie sets the session cookie on the response.
func (m *SessionManager) SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.useHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.duration.Seconds()),
	})
}

// ShouldRotate checks if the session token should be rotated based on its age.
// Returns true if the token is older than half the session duration.
func (m *SessionManager) ShouldRotate(claims *SessionClaims) bool {
	if claims == nil || claims.IssuedAt == nil {
		return false
	}
	age := time.Since(claims.IssuedAt.Time)
	return age > m.rotateAt
}

// RotateSession creates a new session token with refreshed expiration.
func (m *SessionManager) RotateSession(claims *SessionClaims) (string, error) {
	return m.CreateSession(claims.Username, claims.Role, claims.Provider)
}

// ClearSessionCookie removes the session cookie.
func (m *SessionManager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// GetSessionFromRequest extracts and validates the session from a request.
func (m *SessionManager) GetSessionFromRequest(r *http.Request) (*SessionClaims, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie")
	}

	return m.ValidateSession(cookie.Value)
}

