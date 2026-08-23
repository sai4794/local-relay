package config

import (
	"gopkg.in/yaml.v3"
)

var defaultConfig = &Config{
	Server: ServerConfig{
		HTTP:   "127.0.0.1:18080",
		SOCKS5: "127.0.0.1:11080",
	},
	Backend: BackendConfig{
		Type:          "tor",
		Address:       "127.0.0.1:9050",
		ControlAddr:   "127.0.0.1:9051",
		ControlCookie: "/home/stb/tor/data/control_auth_cookie",
		CircuitCount:  3,
		MaxCircuitAge: 50,
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
		MaxBodySize: 32 << 20, // 32MB
		RateLimit:   50,
		RateBurst:   100,
	},
	Logging: LoggingConfig{
		Level:  "info",
		Format: "json",
	},
	Health: HealthConfig{
		Enabled: true,
		Address: "127.0.0.1:18888",
	},
	Metrics: MetricsConfig{
		Enabled: false,
		Path:    "/_/metrics",
		Address: "127.0.0.1:9090",
	},
}

func loadDefaults(cfg *Config) error {
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}
