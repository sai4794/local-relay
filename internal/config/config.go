package config

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Backend   BackendConfig   `yaml:"backend"`
	MultiTor  MultiTorConfig  `yaml:"multi_tor"`
	Bypass    BypassConfig    `yaml:"bypass"`
	Rotation  RotationConfig  `yaml:"rotation"`
	Auth      AuthConfig      `yaml:"auth"`
	Security  SecurityConfig  `yaml:"security"`
	Logging   LoggingConfig   `yaml:"logging"`
	Health    HealthConfig    `yaml:"health"`
	Metrics   MetricsConfig   `yaml:"metrics"`
}

type ServerConfig struct {
	HTTP   string `yaml:"http"`
	SOCKS5 string `yaml:"socks5"`
}

type BackendConfig struct {
	Type           string            `yaml:"type"`
	Address        string            `yaml:"address"`
	Options        map[string]string `yaml:"options"`
	CircuitCount   int               `yaml:"circuit_count"`
	MaxCircuitAge  int               `yaml:"max_circuit_age"`
}

// MultiTorConfig configures multiple Tor daemon instances.
type MultiTorConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Binary        string `yaml:"binary"`
	DataDir       string `yaml:"data_dir"`
	BasePort      int    `yaml:"base_port"`
	ControlBase   int    `yaml:"control_base"`
	MaxInstances  int    `yaml:"max_instances"`
	RotateAfter   int    `yaml:"rotate_after"`
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
	RequestTimeout  int      `yaml:"request_timeout"`
}

type LoggingConfig struct {
	Level          string   `yaml:"level"`
	Format         string   `yaml:"format"`
	RedactHeaders  []string `yaml:"redact_headers"`
	MaxBodyLogSize int      `yaml:"max_body_log_size"`
}

type HealthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
}

// MetricsConfig configures Prometheus metrics.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

var defaultConfig = &Config{
	Server: ServerConfig{
		HTTP:   "127.0.0.1:18080",
		SOCKS5: "127.0.0.1:11080",
	},
	Backend: BackendConfig{
		Type:           "tor",
		Address:        "127.0.0.1:9050",
		CircuitCount:   3,
		MaxCircuitAge:  50,
	},
	MultiTor: MultiTorConfig{
		Enabled:      false,
		Binary:       "tor",
		DataDir:      "/tmp/local-relay-tor",
		BasePort:     9050,
		ControlBase:  9051,
		MaxInstances: 3,
		RotateAfter:  50,
	},
	Rotation: RotationConfig{
		Enabled:  true,
		Interval: 10,
	},
	Auth: AuthConfig{
		Enabled: false,
		APIKey:  "",
	},
	Security: SecurityConfig{
		BlockedNetworks: []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"::1/128",
			"fc00::/7",
			"fe80::/10",
		},
		MaxBodySize:    32 << 20, // 32MB
		RequestTimeout: 300,
	},
	Logging: LoggingConfig{
		Level:          "info",
		Format:         "json",
		RedactHeaders:  []string{"Authorization", "X-Api-Key", "Cookie", "Proxy-Authorization", "Set-Cookie"},
		MaxBodyLogSize: 200,
	},
	Health: HealthConfig{
		Enabled: true,
		Address: "127.0.0.1:18888",
	},
	Metrics: MetricsConfig{
		Enabled: false,
		Path:    "/_/metrics",
	},
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
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	applyEnvOverrides(cfg)

	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func loadDefaults(cfg *Config) error {
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PROXY_HTTP"); v != "" {
		cfg.Server.HTTP = v
	}
	if v := os.Getenv("PROXY_SOCKS5"); v != "" {
		cfg.Server.SOCKS5 = v
	}
	if v := os.Getenv("PROXY_BACKEND_ADDR"); v != "" {
		cfg.Backend.Address = v
	}
	if v := os.Getenv("PROXY_AUTH_KEY"); v != "" {
		cfg.Auth.APIKey = v
		cfg.Auth.Enabled = true
	}
	if v := os.Getenv("PROXY_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("PROXY_HEALTH_ADDR"); v != "" {
		cfg.Health.Address = v
	}
	if v := os.Getenv("TOR_BINARY"); v != "" {
		cfg.MultiTor.Binary = v
	}
}

func Validate(cfg *Config) error {
	validBackendTypes := map[string]bool{"tor": true, "socks5": true, "http": true}
	if !validBackendTypes[cfg.Backend.Type] {
		return fmt.Errorf("backend.type must be one of: tor, socks5, http")
	}

	if err := validateAddress(cfg.Server.HTTP, "server.http"); err != nil {
		return err
	}
	if err := validateAddress(cfg.Server.SOCKS5, "server.socks5"); err != nil {
		return err
	}

	// Validate backend address (not needed for multi-tor mode)
	if !cfg.MultiTor.Enabled {
		if err := validateAddress(cfg.Backend.Address, "backend.address"); err != nil {
			return err
		}
		if cfg.Server.HTTP == cfg.Backend.Address {
			return fmt.Errorf("server.http and backend.address cannot be the same")
		}
		if cfg.Server.SOCKS5 == cfg.Backend.Address {
			return fmt.Errorf("server.socks5 and backend.address cannot be the same")
		}
	}

	if cfg.Server.HTTP == cfg.Server.SOCKS5 {
		return fmt.Errorf("server.http and server.socks5 cannot use the same address")
	}

	// Validate multi-tor config
	if cfg.MultiTor.Enabled {
		if cfg.MultiTor.Binary == "" {
			return fmt.Errorf("multi_tor.binary must not be empty")
		}
		if cfg.MultiTor.MaxInstances < 1 {
			return fmt.Errorf("multi_tor.max_instances must be >= 1")
		}
		if _, err := exec.LookPath(cfg.MultiTor.Binary); err != nil {
			return fmt.Errorf("multi_tor.binary not found in PATH: %w", err)
		}
	}

	// Validate circuit pool config
	if cfg.Backend.CircuitCount < 1 {
		return fmt.Errorf("backend.circuit_count must be >= 1")
	}
	if cfg.Backend.MaxCircuitAge < 1 {
		return fmt.Errorf("backend.max_circuit_age must be >= 1")
	}

	if cfg.Health.Enabled {
		if err := validateAddress(cfg.Health.Address, "health.address"); err != nil {
			return err
		}
	}

	if cfg.Rotation.Enabled && cfg.Rotation.Interval < 1 {
		return fmt.Errorf("rotation.interval must be >= 1")
	}

	if cfg.Auth.Enabled && len(cfg.Auth.APIKey) < 16 {
		return fmt.Errorf("auth.api_key must be at least 16 characters")
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[cfg.Logging.Level] {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error")
	}

	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[cfg.Logging.Format] {
		return fmt.Errorf("logging.format must be one of: json, text")
	}

	// Validate blocked networks
	for _, cidr := range cfg.Security.BlockedNetworks {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("security.blocked_networks: invalid CIDR %q: %w", cidr, err)
		}
	}

	return nil
}

func validateAddress(addr, field string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: invalid address format: %w", field, err)
	}
	if host == "" {
		return fmt.Errorf("%s: host cannot be empty", field)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%s: invalid port: %s", field, port)
	}
	return nil
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
