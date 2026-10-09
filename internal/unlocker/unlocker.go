// Package unlocker defines pluggable ways to unwrap the vault DEK.
package unlocker

import (
	"fmt"
	"sort"
	"sync"
)

// Unlocker wraps and unwraps the vault DEK using some secret factor.
type Unlocker interface {
	Name() string
	// Enroll wraps dek and returns the blob to store in the vault header.
	Enroll(dek []byte) ([]byte, error)
	// Unlock unwraps the DEK from a blob produced by Enroll.
	Unlock(blob []byte) ([]byte, error)
	// Available reports whether this unlocker can run on this machine.
	Available() bool
}

var (
	mu       sync.RWMutex
	registry = map[string]Unlocker{}
)

// Register adds u to the registry, replacing any unlocker with the same name.
func Register(u Unlocker) {
	mu.Lock()
	defer mu.Unlock()
	registry[u.Name()] = u
}

// Get returns the registered unlocker with the given name.
func Get(name string) (Unlocker, error) {
	mu.RLock()
	defer mu.RUnlock()
	u, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unlocker: unknown %q", name)
	}
	return u, nil
}

// Names returns registered unlocker names, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
