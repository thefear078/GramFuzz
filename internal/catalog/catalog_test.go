package catalog_test

import (
	"reflect"
	"testing"

	"github.com/kiurakku/GramFuzz/internal/catalog"
	"github.com/kiurakku/GramFuzz/internal/config"
)

// configKeys reflects every json toggle in config.ModulesConfig.
func configKeys(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	typ := reflect.TypeOf(config.ModulesConfig{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		// strip ,omitempty etc.
		for j := 0; j < len(tag); j++ {
			if tag[j] == ',' {
				tag = tag[:j]
				break
			}
		}
		keys[tag] = true
	}
	return keys
}

// TestCatalogKeysExistInConfig guards against a catalog entry pointing at a
// config toggle that was renamed or removed.
func TestCatalogKeysExistInConfig(t *testing.T) {
	cfgKeys := configKeys(t)
	for _, m := range catalog.All() {
		if m.ConfigKey == "" {
			continue
		}
		if !cfgKeys[m.ConfigKey] {
			t.Errorf("module %q references config key %q which is not in ModulesConfig", m.ID, m.ConfigKey)
		}
	}
}

// TestEveryConfigKeyIsDocumented guards the other direction: a new toggle in
// ModulesConfig must have at least one catalog entry describing it, so the
// `modules` command and the docs never silently omit a capability.
func TestEveryConfigKeyIsDocumented(t *testing.T) {
	documented := catalog.ConfigKeys()
	for key := range configKeys(t) {
		if !documented[key] {
			t.Errorf("config toggle %q has no catalog entry; add one in internal/catalog/catalog.go", key)
		}
	}
}

// TestEngineModulesAreOrdered ensures pipeline phases are contiguous and
// strictly increasing, so the `[n/total]` progress output stays sensible.
func TestEngineModulesAreOrdered(t *testing.T) {
	last := 0
	for _, m := range catalog.Engine() {
		if m.Phase <= 0 {
			t.Fatalf("engine module %q has non-positive phase %d", m.ID, m.Phase)
		}
		if m.Phase < last {
			t.Fatalf("engine module %q phase %d is out of order (after %d)", m.ID, m.Phase, last)
		}
		last = m.Phase
	}
}

// TestIDsAreUnique keeps module slugs unique (they are used as stable refs).
func TestIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range catalog.All() {
		if seen[m.ID] {
			t.Errorf("duplicate module ID %q", m.ID)
		}
		seen[m.ID] = true
	}
}
