package module

import (
	"errors"
	"fmt"
	"sort"
)

// Registry holds the modules available to a worker.
//
// It is deliberately not a package-level global filled by init() functions:
// the worker builds one explicitly at startup, and each test builds its own,
// so nothing is shared by accident. A Registry is meant to be filled once at
// startup and then only read; it is not safe for concurrent Register calls.
type Registry struct {
	modules map[string]Module
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{modules: make(map[string]Module)}
}

// Register adds m. It rejects a nil module, an invalid Info, and an ID that is
// already registered.
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
