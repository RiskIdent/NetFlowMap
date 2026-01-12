package netflow

import (
	"fmt"
	"sync"
	"time"
)

// TemplateCache stores NetFlow v9 templates.
// Templates are keyed by source IP and template ID.
type TemplateCache struct {
	mu        sync.RWMutex
	templates map[string]*Template // key: "sourceIP:templateID"
	maxAge    time.Duration
}

// NewTemplateCache creates a new template cache.
func NewTemplateCache() *TemplateCache {
	return &TemplateCache{
		templates: make(map[string]*Template),
		maxAge:    30 * time.Minute, // Templates expire after 30 minutes
	}
}

// cacheKey generates a cache key for a template.
func cacheKey(sourceIP string, templateID uint16) string {
	return fmt.Sprintf("%s:%d", sourceIP, templateID)
}

// Set stores a template in the cache.
func (tc *TemplateCache) Set(sourceIP string, tmpl *Template) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tmpl.SourceIP = sourceIP
	tmpl.LastSeen = time.Now()

	key := cacheKey(sourceIP, tmpl.ID)
	tc.templates[key] = tmpl
}

// Get retrieves a template from the cache.
// Returns nil if the template is not found or has expired.
func (tc *TemplateCache) Get(sourceIP string, templateID uint16) *Template {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	key := cacheKey(sourceIP, templateID)
	tmpl, ok := tc.templates[key]
	if !ok {
		return nil
	}

	// Check if template has expired
	if time.Since(tmpl.LastSeen) > tc.maxAge {
		return nil
	}

	return tmpl
}

// Delete removes a template from the cache.
func (tc *TemplateCache) Delete(sourceIP string, templateID uint16) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	key := cacheKey(sourceIP, templateID)
	delete(tc.templates, key)
}

// Cleanup removes expired templates from the cache.
func (tc *TemplateCache) Cleanup() int {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	removed := 0
	now := time.Now()

	for key, tmpl := range tc.templates {
		if now.Sub(tmpl.LastSeen) > tc.maxAge {
			delete(tc.templates, key)
			removed++
		}
	}

	return removed
}

// Count returns the number of templates in the cache.
func (tc *TemplateCache) Count() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.templates)
}

// CountForSource returns the number of templates for a specific source.
func (tc *TemplateCache) CountForSource(sourceIP string) int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	count := 0
	for _, tmpl := range tc.templates {
		if tmpl.SourceIP == sourceIP {
			count++
		}
	}
	return count
}


