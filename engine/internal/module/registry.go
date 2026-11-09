package module

import (
	"errors"
	"fmt"
	"sort"
)

// Registry holds the modules available to a worker, and their check
// catalogs.
//
// It is deliberately not a package-level global filled by init() functions:
// the worker builds one explicitly at startup, and each test builds its own,
// so nothing is shared by accident. A Registry is meant to be filled once at
// startup and then only read; it is not safe for concurrent Register calls.
type Registry struct {
	modules map[string]Module
	checks  map[string]string // check ID -> module ID
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{modules: make(map[string]Module), checks: make(map[string]string)}
}

// Register adds m. It rejects a nil module, an invalid Info, an ID that is
// already registered, and an invalid check catalog. Check IDs must be unique
// across modules: reports and translations look checks up by ID. A module
// may declare no checks if it only reports assets (it then cannot return
// findings).
func (r *Registry) Register(m Module) error {
	if m == nil {
		return errors.New("register module: nil module")
	}
	info := m.Info()
	if !isSlug(info.ID) {
		return fmt.Errorf("register module: id %q must be a non-empty lowercase slug (a-z, 0-9, -)", info.ID)
	}
	if info.Name == "" {
		return fmt.Errorf("register module %q: empty name", info.ID)
	}
	if !info.Kind.Valid() {
		return fmt.Errorf("register module %q: kind %q: %w", info.ID, info.Kind, ErrInvalidKind)
	}
	if _, exists := r.modules[info.ID]; exists {
		return fmt.Errorf("register module %q: already registered", info.ID)
	}
	seen := make(map[string]bool, len(info.Checks))
	for _, c := range info.Checks {
		switch {
		case !isSlug(c.ID):
			return fmt.Errorf("register module %q: check id %q must be a lowercase slug", info.ID, c.ID)
		case seen[c.ID]:
			return fmt.Errorf("register module %q: check %q declared twice", info.ID, c.ID)
		case r.checks[c.ID] != "":
			return fmt.Errorf("register module %q: check %q already declared by module %q", info.ID, c.ID, r.checks[c.ID])
		case !c.Category.Valid():
			return fmt.Errorf("register module %q: check %q: unknown category %q", info.ID, c.ID, c.Category)
		case !c.Severity.Valid():
			return fmt.Errorf("register module %q: check %q: unknown severity %q", info.ID, c.ID, c.Severity)
		case c.Title == "":
			return fmt.Errorf("register module %q: check %q: empty title", info.ID, c.ID)
		}
		seen[c.ID] = true
	}
	for _, c := range info.Checks {
		r.checks[c.ID] = info.ID
	}
	r.modules[info.ID] = m
	return nil
}

// Get returns the module with the given ID.
func (r *Registry) Get(id string) (Module, bool) {
	m, ok := r.modules[id]
	return m, ok
}

// All returns every registered module, sorted by ID so the order is stable
// (Go map iteration order is random).
func (r *Registry) All() []Module {
	all := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		all = append(all, m)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Info().ID < all[j].Info().ID })
	return all
}

// isSlug reports whether s is a non-empty string of a-z, 0-9 and '-'.
// It matches the rule finding.Validate applies to module IDs.
func isSlug(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
