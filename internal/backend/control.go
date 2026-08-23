package backend

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// controlTimeout bounds every control-port operation (connect, auth,
// each command reply). Tor answers these instantly on a healthy daemon;
// the deadline exists so a wedged daemon cannot leak goroutines.
const controlTimeout = 5 * time.Second

// TorControlClient issues commands to a single Tor daemon control port.
//
// Authentication is attempted in Tor's conventional order:
//  1. COOKIE auth  — when Cookie returns a valid 32-byte cookie
//  2. password auth — quoted, when Password is set
//  3. empty auth   — for daemons without authentication configured
//
// A fresh TCP connection is used per invocation; Tor control usage here is
// one SIGNAL every few seconds at most, so connection setup cost is noise
// and statelessness avoids stale-connection handling entirely.
type TorControlClient struct {
	Addr     string
	Password string
	// Cookie optionally supplies the raw control-auth cookie. Returning
	// no cookie falls through to Password / empty auth.
	Cookie func() ([]byte, bool)
}

// NewTorControlClient builds a client for the given control address.
func NewTorControlClient(addr, password string, cookie func() ([]byte, bool)) *TorControlClient {
	return &TorControlClient{Addr: addr, Password: password, Cookie: cookie}
}

// SignalNEWNYM requests a fresh circuit. When dropGuards is true a
// DROPGUARDS is issued first to clear stalled guard nodes; DROPGUARDS
// failure is tolerated (it is an optimization, not a requirement).
func (c *TorControlClient) SignalNEWNYM(dropGuards bool) error {
	if c.Addr == "" {
		return fmt.Errorf("tor control port not configured")
	}

	conn, err := net.DialTimeout("tcp", c.Addr, controlTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to control port: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(controlTimeout))

	reader := bufio.NewReader(conn)

	if err := c.authenticate(conn, reader); err != nil {
		return err
	}

	if dropGuards {
		if err := writeCommand(conn, reader, "DROPGUARDS"); err != nil {
			// Non-fatal: proceed with NEWNYM even if guard dropping failed.
			_ = err
		}
	}

	return writeCommand(conn, reader, "SIGNAL NEWNYM")
}

// authenticate performs cookie → password → empty AUTHENTICATE and consumes
// the single-line reply.
func (c *TorControlClient) authenticate(conn net.Conn, reader *bufio.Reader) error {
	authSent := false

	if c.Cookie != nil {
		if cookie, ok := c.Cookie(); ok && len(cookie) == cookieSize {
			fmt.Fprintf(conn, "AUTHENTICATE %s\r\n", hex.EncodeToString(cookie))
			authSent = true
		}
	}
	if !authSent && c.Password != "" {
		fmt.Fprintf(conn, "AUTHENTICATE %q\r\n", c.Password)
		authSent = true
	}
	if !authSent {
		fmt.Fprintf(conn, "AUTHENTICATE\r\n")
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("auth failed: %w", err)
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("auth rejected: %s", strings.TrimSpace(resp))
	}
	return nil
}

// writeCommand sends one control command and validates its 250 reply.
func writeCommand(conn net.Conn, reader *bufio.Reader, cmd string) error {
	if _, err := fmt.Fprintf(conn, "%s\r\n", cmd); err != nil {
		return fmt.Errorf("%s write: %w", cmd, err)
	}
	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("%s failed: %w", cmd, err)
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("%s rejected: %s", cmd, strings.TrimSpace(resp))
	}
	return nil
}

// cookieSize is the fixed length of a Tor control-auth cookie.
const cookieSize = 32

// readCookieFile loads a control-auth cookie from disk.
func readCookieFile(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	cookie, err := os.ReadFile(path)
	if err != nil || len(cookie) != cookieSize {
		return nil, false
	}
	return cookie, true
}
