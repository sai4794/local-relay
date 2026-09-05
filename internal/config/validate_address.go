package config

import (
	"fmt"
	"net"
	"strconv"
)

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

func parsePort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return p
}
