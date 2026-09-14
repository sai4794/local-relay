package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// blocked_networks triple-sync: defaults.go vs config.yaml must match exactly.
// The yaml list replaces (not merges with) the defaults, so any drift means
// file-loaded runtime enforcement differs from default-loaded enforcement —
// silently, for ranges like 0.0.0.0/8, 100.64.0.0/10, 198.18.0.0/15.
func TestBlockedNetworks_DefaultsMatchConfigYAML(t *testing.T) {
	def := &Config{}
	if err := loadDefaults(def); err != nil {
		t.Fatalf("loading defaults: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatalf("reading config.yaml: %v", err)
	}
	var file struct {
		Security struct {
			BlockedNetworks []string `yaml:"blocked_networks"`
		} `yaml:"security"`
	}
	if err := yaml.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parsing config.yaml: %v", err)
	}
	a := append([]string(nil), def.Security.BlockedNetworks...)
	b := append([]string(nil), file.Security.BlockedNetworks...)
	sort.Strings(a)
	sort.Strings(b)
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Errorf("blocked_networks drift:\ndefaults.go: %v\nconfig.yaml:  %v", a, b)
	}
	// Spot-check the easy-to-drop ranges that motivated the sync comment.
	for _, want := range []string{"0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15"} {
		found := false
		for _, c := range b {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("config.yaml missing %q", want)
		}
	}
}
