package config

import (
	"fmt"
	"net"
	"os/exec"
)

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
