// Package auth provides authentication and authorization functionality.
package auth

import (
	"fmt"
	"os"
	"sync"

	"github.com/RiskIdent/NetFlowMap/internal/logging"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// dummyHash is used for timing-safe comparison when user doesn't exist
// This prevents username enumeration via timing attacks
var dummyHash = []byte("$2a$10$dummyhashfordummycomparisononly")

// knownWeakHashes contains hashes of common weak passwords that should trigger warnings
var knownWeakHashes = map[string]string{
	// admin:admin from example file
	"$2a$10$N9qo8uLOickgx2ZMRZoMy.MQDOPVHoQV8r8K0N0oHFjJB.ey4vB.S": "admin",
	// viewer:viewer from example file
	"$2a$10$K.0HwpsoPDgaB/i0bW.0Vu6RNJOqq7B.0ukEAjA8mRGVHmDGPWBsC": "viewer",
}

// Role represents a user's authorization level.
type Role string

const (
	RoleAnonymous Role = "anonymous"
	RoleUser      Role = "user"
	RoleAdmin     Role = "admin"
)

// User represents a user account.
type User struct {
	Username string `yaml:"username" json:"username"`
	Role     Role   `yaml:"role" json:"role"`
	// PasswordHash is the bcrypt hash of the password (only for local users)
	PasswordHash string `yaml:"password_hash,omitempty" json:"-"`
}

// UsersFile represents the structure of users.yml.
type UsersFile struct {
	Users []User `yaml:"users"`
}

// UserStore manages local user accounts.
type UserStore struct {
	mu       sync.RWMutex
	users    map[string]*User
	filePath string
}

// NewUserStore creates a new user store from a users.yml file.
func NewUserStore(filePath string) (*UserStore, error) {
	store := &UserStore{
		users:    make(map[string]*User),
		filePath: filePath,
	}

	if err := store.Load(); err != nil {
		return nil, err
	}

	return store, nil
}

// Load reads and parses the users file.
func (s *UserStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if file exists
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		// File doesn't exist, start with empty store
		s.users = make(map[string]*User)
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read users file: %w", err)
	}

	var usersFile UsersFile
	if err := yaml.Unmarshal(data, &usersFile); err != nil {
		return fmt.Errorf("failed to parse users file: %w", err)
	}

	// Build user map
	s.users = make(map[string]*User)
	for i := range usersFile.Users {
		user := &usersFile.Users[i]
		if user.Username == "" {
			continue
		}
		// Validate role
		if user.Role != RoleUser && user.Role != RoleAdmin {
			user.Role = RoleUser // Default to user
		}

		// Check for known weak passwords from example files
		if weakPwd, isWeak := knownWeakHashes[user.PasswordHash]; isWeak {
			logging.Warning("SECURITY WARNING: User has a known weak password from example file!",
				"username", user.Username,
				"weak_password", weakPwd,
				"action", "Please change the password immediately using --hash-password")
		}

		s.users[user.Username] = user
	}

	return nil
}

// Authenticate verifies a username and password combination.
// Returns the user if successful, nil otherwise.
// Uses timing-safe comparison to prevent username enumeration.
func (s *UserStore) Authenticate(username, password string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]

	// Always perform password comparison to prevent timing attacks
	// that could reveal whether a username exists
	var hashToCompare []byte
	if !exists || user.PasswordHash == "" {
		// Use dummy hash to maintain consistent timing
		hashToCompare = dummyHash
	} else {
		hashToCompare = []byte(user.PasswordHash)
	}

	err := bcrypt.CompareHashAndPassword(hashToCompare, []byte(password))

	// Only return user if both username exists and password matches
	if !exists || user.PasswordHash == "" || err != nil {
		return nil
	}

	return user
}

// GetUser returns a user by username.
func (s *UserStore) GetUser(username string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.users[username]
}

// HashPassword generates a bcrypt hash for a password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

