package web

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/kai/netflowmap/internal/auth"
	"github.com/kai/netflowmap/internal/logging"
)

// AuthConfigResponse is the response for /auth/config.
type AuthConfigResponse struct {
	Enabled   bool `json:"enabled"`
	HasOIDC   bool `json:"has_oidc"`
	HasLocal  bool `json:"has_local"`
}

// CurrentUserResponse is the response for /auth/me.
type CurrentUserResponse struct {
	Authenticated bool      `json:"authenticated"`
	Username      string    `json:"username,omitempty"`
	Role          auth.Role `json:"role"`
}

// handleAuthConfig returns the auth configuration for the frontend.
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	response := AuthConfigResponse{
		Enabled: false,
	}

	if s.authService != nil && s.authService.IsEnabled() {
		response.Enabled = true
		response.HasOIDC = s.authService.HasOIDC()
		response.HasLocal = s.authService.HasLocalAuth()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetCurrentUser returns the current user info.
func (s *Server) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	response := CurrentUserResponse{
		Authenticated: user.Role != auth.RoleAnonymous,
		Username:      user.Username,
		Role:          user.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleLoginPage serves the login page.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	user := auth.GetUserFromContext(r.Context())
	if user.Role != auth.RoleAnonymous {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	hasOIDC := s.authService != nil && s.authService.HasOIDC()
	hasLocal := s.authService != nil && s.authService.HasLocalAuth()
	errorMsg := r.URL.Query().Get("error")

	// Simple login page template
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - NetFlowMap</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --border-color: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            font-size: 1.8rem;
            color: var(--accent-green);
        }
        .logo p {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 5px;
        }
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9rem;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: var(--accent-blue);
        }
        button {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        button:hover { opacity: 0.9; }
        .btn-primary {
            background: var(--accent-blue);
            color: white;
        }
        .btn-oidc {
            background: var(--accent-green);
            color: white;
            margin-top: 15px;
        }
        .divider {
            display: flex;
            align-items: center;
            margin: 25px 0;
            color: var(--text-secondary);
        }
        .divider::before, .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: var(--border-color);
        }
        .divider span {
            padding: 0 15px;
            font-size: 0.85rem;
        }
        .anonymous-note {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        .anonymous-note a {
            color: var(--accent-blue);
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🌐 NetFlowMap</h1>
            <p>Network Traffic Visualization</p>
        </div>

        {{if .Error}}
        <div class="error">{{.Error}}</div>
        {{end}}

        {{if .HasLocal}}
        <form method="POST" action="/auth/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn-primary">Login</button>
        </form>
        {{end}}

        {{if and .HasOIDC .HasLocal}}
        <div class="divider"><span>or</span></div>
        {{end}}

        {{if .HasOIDC}}
        <a href="/auth/oidc/login">
            <button type="button" class="btn-oidc">Login with SSO</button>
        </a>
        {{end}}

        <div class="anonymous-note">
            <a href="/">Continue without login</a><br>
            <small>(Limited access - IP addresses hidden)</small>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("login").Parse(tmpl)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	data := struct {
		HasOIDC  bool
		HasLocal bool
		Error    string
	}{
		HasOIDC:  hasOIDC,
		HasLocal: hasLocal,
		Error:    errorMsg,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// handleLocalLogin handles local username/password authentication.
func (s *Server) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil || !s.authService.HasLocalAuth() {
		http.Redirect(w, r, "/auth/login?error=Local+authentication+not+available", http.StatusFound)
		return
	}

	// Get client IP for rate limiting
	clientIP := r.RemoteAddr
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	}

	// Check rate limiting
	if s.rateLimiter != nil && s.rateLimiter.IsBlocked(clientIP) {
		blockedUntil := s.rateLimiter.BlockedUntil(clientIP)
		logging.Warning("login blocked due to rate limiting", "ip", clientIP, "blocked_until", blockedUntil)
		http.Redirect(w, r, "/auth/login?error=Too+many+failed+attempts.+Please+try+again+later.", http.StatusFound)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Redirect(w, r, "/auth/login?error=Username+and+password+required", http.StatusFound)
		return
	}

	user := s.authService.UserStore().Authenticate(username, password)
	if user == nil {
		// Record failed attempt
		if s.rateLimiter != nil {
			blocked := s.rateLimiter.RecordFailure(clientIP)
			remaining := s.rateLimiter.RemainingAttempts(clientIP)
			logging.Warning("failed login attempt",
				"username", username,
				"ip", clientIP,
				"remaining_attempts", remaining,
				"now_blocked", blocked)

			if blocked {
				http.Redirect(w, r, "/auth/login?error=Too+many+failed+attempts.+Please+try+again+later.", http.StatusFound)
				return
			}
		} else {
			logging.Warning("failed login attempt", "username", username, "ip", clientIP)
		}

		http.Redirect(w, r, "/auth/login?error=Invalid+username+or+password", http.StatusFound)
		return
	}

	// Clear rate limit on successful login
	if s.rateLimiter != nil {
		s.rateLimiter.RecordSuccess(clientIP)
	}

	// Create session
	token, err := s.authService.SessionManager().CreateSession(user.Username, user.Role, "local")
	if err != nil {
		logging.Error("failed to create session", "error", err)
		http.Redirect(w, r, "/auth/login?error=Session+creation+failed", http.StatusFound)
		return
	}

	s.authService.SessionManager().SetSessionCookie(w, token)
	logging.Info("user logged in", "username", user.Username, "role", user.Role, "provider", "local", "ip", clientIP)

	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout handles user logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.authService != nil && s.authService.SessionManager() != nil {
		s.authService.SessionManager().ClearSessionCookie(w)
	}
	
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleOIDCLogin initiates OIDC authentication.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil || !s.authService.HasOIDC() {
		http.Redirect(w, r, "/auth/login?error=OIDC+not+configured", http.StatusFound)
		return
	}

	authURL, _ := s.authService.OIDCProvider().GetAuthURL()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback handles the OIDC callback.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil || !s.authService.HasOIDC() {
		http.Redirect(w, r, "/auth/login?error=OIDC+not+configured", http.StatusFound)
		return
	}

	// Check for error from provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		logging.Warning("OIDC error", "error", errParam, "description", errDesc)
		http.Redirect(w, r, "/auth/login?error="+errParam, http.StatusFound)
		return
	}

	user, err := s.authService.OIDCProvider().HandleCallback(r.Context(), r)
	if err != nil {
		logging.Error("OIDC callback failed", "error", err)
		http.Redirect(w, r, "/auth/login?error=Authentication+failed", http.StatusFound)
		return
	}

	// Create session
	token, err := s.authService.SessionManager().CreateSession(user.Username, user.Role, "oidc")
	if err != nil {
		logging.Error("failed to create session", "error", err)
		http.Redirect(w, r, "/auth/login?error=Session+creation+failed", http.StatusFound)
		return
	}

	s.authService.SessionManager().SetSessionCookie(w, token)
	logging.Info("user logged in", "username", user.Username, "role", user.Role, "provider", "oidc")
	
	http.Redirect(w, r, "/", http.StatusFound)
}

