package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// parseEnv applies a parsed environment override. Empty values mean "unset"
// and leave the file/default value alone. A non-empty but unparseable value
// is an error: silently keeping a default hid operator typos (issue M-12).
func parseEnv[T any](name string, parse func(string) (T, error), apply func(T)) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	parsed, err := parse(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("invalid %s=%q: %w", name, v, err)
	}
	apply(parsed)
	return nil
}

// applyEnvOverrides applies all supported environment variables over the
// file/default config. Unsupported values fail fast with the variable name.
func applyEnvOverrides(cfg *Config) error {
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
		// Legacy behavior: supplying a key enables auth unless the
		// explicit toggle is present (issue M-02).
		if os.Getenv("PROXY_AUTH_ENABLED") == "" {
			cfg.Auth.Enabled = true
		}
	}
	if err := parseEnv("PROXY_AUTH_ENABLED", strconv.ParseBool, func(b bool) {
		cfg.Auth.Enabled = b
	}); err != nil {
		return err
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
	if v := os.Getenv("TOR_LIBRARY_PATH"); v != "" {
		cfg.MultiTor.LibraryPath = v
	}

	for _, override := range []func() error{
		func() error {
			return parseEnv("POOL_ENABLED", strconv.ParseBool, func(b bool) { cfg.Pool.Enabled = b })
		},
		func() error {
			return parseEnv("POOL_EWMA_ALPHA", func(s string) (float64, error) { return strconv.ParseFloat(s, 64) },
				func(f float64) { cfg.Pool.EWMAAlpha = f })
		},
		func() error {
			return parseEnv("POOL_LATENCY_REF_MS", func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) },
				func(n int64) { cfg.Pool.LatencyRefMs = n })
		},
		func() error {
			return parseEnv("POOL_MIN_SAMPLES", func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) },
				func(n int64) { cfg.Pool.MinSamples = n })
		},
		func() error {
			return parseEnv("POOL_MIN_QUALITY", func(s string) (float64, error) { return strconv.ParseFloat(s, 64) },
				func(f float64) { cfg.Pool.MinQuality = f })
		},
		func() error {
			return parseEnv("POOL_SELECTION", func(s string) (string, error) { return s, nil },
				func(s string) { cfg.Pool.Selection = s })
		},
		func() error {
			return parseEnv("POOL_PO2_SAMPLES", strconv.Atoi, func(n int) { cfg.Pool.Po2Samples = n })
		},
		func() error {
			return parseEnv("POOL_QUARANTINE_AFTER_FAILS", strconv.Atoi,
				func(n int) { cfg.Pool.QuarantineAfterFails = n })
		},
		func() error {
			return parseEnv("POOL_QUARANTINE_SECS", func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) },
				func(n int64) { cfg.Pool.QuarantineSecs = n })
		},
		func() error {
			return parseEnv("POOL_MAX_QUARANTINE_SECS", func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) },
				func(n int64) { cfg.Pool.MaxQuarantineSecs = n })
		},
		func() error {
			return parseEnv("POOL_PROBATION_PROBES", strconv.Atoi, func(n int) { cfg.Pool.ProbationProbes = n })
		},
	} {
		if err := override(); err != nil {
			return err
		}
	}
	return nil
}
