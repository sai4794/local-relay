package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig     `yaml:"server"`
	Backend  BackendConfig    `yaml:"backend"`
	MultiTor MultiTorConfig   `yaml:"multi_tor"`
	Pool     PoolTuningConfig `yaml:"pool"`
	Bypass   BypassConfig     `yaml:"bypass"`
	Rotation RotationConfig   `yaml:"rotation"`
	Auth     AuthConfig       `yaml:"auth"`
	Security SecurityConfig   `yaml:"security"`
	Logging  LoggingConfig    `yaml:"logging"`
	Health   HealthConfig     `yaml:"health"`
	Metrics  MetricsConfig    `yaml:"metrics"`
}

type ServerConfig struct {
	HTTP   string `yaml:"http"`
	SOCKS5 string `yaml:"socks5"`
}

type BackendConfig struct {
	Type          string            `yaml:"type"`
	Address       string            `yaml:"address"`
	ControlAddr   string            `yaml:"control_addr"`
	ControlCookie string            `yaml:"control_cookie_path"`
	Options       map[string]string `yaml:"options"`
	CircuitCount  int               `yaml:"circuit_count"`
	MaxCircuitAge int               `yaml:"max_circuit_age"`
}

// MultiTorConfig configures multiple Tor daemon instances.
type MultiTorConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Binary       string `yaml:"binary"`
	DataDir      string `yaml:"data_dir"`
	BasePort     int    `yaml:"base_port"`
	ControlBase  int    `yaml:"control_base"`
	MaxInstances int    `yaml:"max_instances"`
	RotateAfter  int    `yaml:"rotate_after"`
	// LibraryPath, when non-empty, is exported as LD_LIBRARY_PATH to the
	// spawned Tor children (needed when tor is linked against private libs
	// not on the system loader path). Default empty = inherit parent's env.
	LibraryPath string `yaml:"library_path"`
}

// PoolTuningConfig tunes scored selection + outcome feedback + quarantine
// (the [pool] section). Zero values mean defaults (see defaults.go); the
// kill-switch Enabled=false restores pure least-inflight selection while
// stats keep recording. No ports or binds — usedPorts/loopback validation
// is untouched.
type PoolTuningConfig struct {
	Enabled              bool    `yaml:"enabled"`
	EWMAAlpha            float64 `yaml:"ewma_alpha"`
	LatencyRefMs         int64   `yaml:"latency_ref_ms"`
	MinSamples           int64   `yaml:"min_samples"`
	MinQuality           float64 `yaml:"min_quality"`
	Selection            string  `yaml:"selection"`
	Po2Samples           int     `yaml:"po2_samples"`
	QuarantineAfterFails int     `yaml:"quarantine_after_fails"`
	QuarantineSecs       int64   `yaml:"quarantine_secs"`
	MaxQuarantineSecs    int64   `yaml:"max_quarantine_secs"`
	ProbationProbes      int     `yaml:"probation_probes"`
}

type BypassConfig struct {
	Hosts []string `yaml:"hosts"`
}

type RotationConfig struct {
	Enabled  bool `yaml:"enabled"`
	Interval int  `yaml:"interval"`
}

type AuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
}

// SecurityConfig configures SSRF protection and request limits.
type SecurityConfig struct {
	BlockedNetworks []string `yaml:"blocked_networks"`
	MaxBodySize     int64    `yaml:"max_body_size"`
	RateLimit       int      `yaml:"rate_limit"` // requests/sec per destination host
	RateBurst       int      `yaml:"rate_burst"`
	// FailClosedDNS, when true, blocks hosts that cannot be resolved locally
	// instead of the default advisory fail-open (which keeps Tor-routable
	// domains reachable when the local resolver cannot see them).
	FailClosedDNS bool `yaml:"fail_closed_dns"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type HealthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
}

// MetricsConfig configures Prometheus metrics.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Address string `yaml:"address"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{}
	if err := loadDefaults(cfg); err != nil {
		return nil, fmt.Errorf("loading defaults: %w", err)
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		// Strict decoding: unknown keys are rejected instead of silently
		// dropped. config.yaml is proven strict-clean by
		// TestStrict_ProductionConfigHasOnlyKnownFields. A second YAML
		// document after "---" is also rejected: silently loading only the
		// first would leave an operator's appended override dead with no
		// signal, so fail fast instead.
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
		var extra interface{}
		if err := dec.Decode(&extra); err != io.EOF {
			// err == nil with a non-nil extra: a real second document —
			// silently loading only the first would leave an operator's
			// appended override dead with no signal, so fail fast instead.
			// err != nil (and not EOF): the trailing document marker "---" is
			// followed by unscannable content — also fail fast rather than
			// ignoring operator content we could not even parse. err == nil
			// with a nil extra is just a trailing "---" marker with an empty
			// document, which stays valid.
			if err != nil || extra != nil {
				return nil, fmt.Errorf("parsing config file: multiple YAML documents are not allowed")
			}
		}
	}

	applyEnvOverrides(cfg)

	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *Config) IsTor() bool {
	return c.Backend.Type == "tor"
}

func (c *Config) IsPool() bool {
	return c.Backend.Type == "tor" && c.Backend.CircuitCount > 1 && !c.MultiTor.Enabled
}

func (c *Config) IsMultiTor() bool {
	return c.MultiTor.Enabled
}

func (c *Config) CircuitCount() int {
	if c.Backend.CircuitCount < 1 {
		return 1
	}
	return c.Backend.CircuitCount
}

func (c *Config) MaxCircuitAgeVal() int {
	if c.Backend.MaxCircuitAge < 1 {
		return 50
	}
	return c.Backend.MaxCircuitAge
}

func (c *Config) ConnectionTimeout() time.Duration {
	if c.IsTor() || c.MultiTor.Enabled {
		return 30 * time.Second
	}
	return 10 * time.Second
}

// IsNetworkBlocked checks if an IP is in any blocked CIDR range.
func (c *Config) IsNetworkBlocked(ip net.IP) bool {
	for _, cidrStr := range c.Security.BlockedNetworks {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// MaxBodySizeBytes returns the configured max body size.
func (c *Config) MaxBodySizeBytes() int64 {
	if c.Security.MaxBodySize > 0 {
		return c.Security.MaxBodySize
	}
	return 32 << 20
}
