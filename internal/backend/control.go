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
	// Logf optionally receives non-fatal control-channel notices
	// (e.g. tolerated DROPGUARDS failures).
	Logf func(string, ...interface{})
}

// NewTorControlClient builds a client for the given control address.
func NewTorControlClient(addr, password string, cookie func() ([]byte, bool)) *TorControlClient {
	return &TorControlClient{Addr: addr, Password: password, Cookie: cookie}
}

// VerifyAuth checks control-port authentication without changing state.
// It connects, performs cookie → password → empty AUTHENTICATE, then closes.
// No SIGNAL or other command is issued.
func (c *TorControlClient) VerifyAuth() error {
	if c.Addr == "" {
		return fmt.Errorf("tor control port not configured")
	}

	conn, err := net.DialTimeout("tcp", c.Addr, controlTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to control port: %w", err)
	}
	defer conn.Close()
	// Log-only on failure: the deadline is best-effort hardening so a wedged
	// daemon cannot leak goroutines; the command reply reads still time out
	// via the dial-bounded path, and failing the whole call here would
	// change behavior for callers that previously proceeded.
	if err := conn.SetDeadline(time.Now().Add(controlTimeout)); err != nil && c.Logf != nil {
		c.Logf("tor-control: SetDeadline: %v", err)
	}

	reader := bufio.NewReader(conn)

	return c.authenticate(conn, reader)
}

// SignalNEWNYM requests a fresh circuit. When dropGuards is true a
// DROPGUARDS is issued first to clear stalled guard nodes; DROPGUARDS
// failure is tolerated but surfaced to the caller's log via Logf when set.
func (c *TorControlClient) SignalNEWNYM(dropGuards bool) error {
	if c.Addr == "" {
		return fmt.Errorf("tor control port not configured")
	}

	conn, err := net.DialTimeout("tcp", c.Addr, controlTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to control port: %w", err)
	}
	defer conn.Close()
	// Log-only on failure (see VerifyAuth): best-effort hardening, behavior-preserving.
	if err := conn.SetDeadline(time.Now().Add(controlTimeout)); err != nil && c.Logf != nil {
		c.Logf("tor-control: SetDeadline: %v", err)
	}

	reader := bufio.NewReader(conn)

	if err := c.authenticate(conn, reader); err != nil {
		return err
	}

	if dropGuards {
		if err := writeCommand(conn, reader, "DROPGUARDS"); err != nil && c.Logf != nil {
			// Non-fatal: proceed with NEWNYM even if guard dropping failed.
			c.Logf("tor-control: DROPGUARDS failed (continuing with NEWNYM): %v", err)
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

// readCookieFile loads a control-auth cookie from disk with retry to handle
// Tor's atomic replace race where file is briefly 0 bytes (observed
// "Got authentication cookie with wrong length (0)" warnings).
func readCookieFile(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	for attempt := 0; attempt < 3; attempt++ {
		cookie, err := os.ReadFile(path)
		if err == nil && len(cookie) == cookieSize {
			return cookie, true
		}
		if err == nil && len(cookie) == 0 && attempt < 2 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err != nil {
			return nil, false
		}
		return nil, false
	}
	return nil, false
}
