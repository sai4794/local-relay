package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type SOCKS5Client struct {
	dialer *net.Dialer
}

func NewSOCKS5Client(timeout time.Duration) *SOCKS5Client {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &SOCKS5Client{
		dialer: &net.Dialer{Timeout: timeout},
	}
}

func (c *SOCKS5Client) Connect(ctx context.Context, socksAddr, targetAddr, isoUser string) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, fmt.Errorf("tor socks connect: %w", err)
	}

	// Bound the entire handshake — the dial timeout only covers connect.
	// A Tor instance that accepts TCP but never answers the greeting
	// (wedged-but-listening) would otherwise pin the request goroutine forever.
	if err := conn.SetDeadline(time.Now().Add(c.dialer.Timeout)); err == nil {
		defer conn.SetDeadline(time.Time{})
	}

	if err := c.handshake(conn, targetAddr, isoUser); err != nil {
		conn.Close()
		return nil, err
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	return conn, nil
}

func (c *SOCKS5Client) handshake(conn net.Conn, targetAddr, isoUser string) error {
	methods := []byte{0x00}
	if isoUser != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("greeting read: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", resp[0])
	}

	if isoUser != "" && resp[1] == 0x02 {
		if err := c.auth(conn, isoUser); err != nil {
			return err
		}
	} else if resp[1] != 0x00 {
		return fmt.Errorf("auth method not accepted: %d", resp[1])
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if len(host) > 255 {
		return fmt.Errorf("target host %q exceeds maximum SOCKS5 domain length (255)", host)
	}

	req := make([]byte, 0, 4+1+len(host)+2)
	req = append(req, 0x05, 0x01, 0x00, 0x03)
	req = append(req, byte(len(host)))
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("connect write: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("connect reply header: %w", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		return fmt.Errorf("connect failed: status %d", hdr[1])
	}

	var toSkip int
	switch hdr[3] {
	case 0x01:
		toSkip = net.IPv4len + 2
	case 0x04:
		toSkip = net.IPv6len + 2
	case 0x03:
		dLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, dLen); err != nil {
			return err
		}
		toSkip = int(dLen[0]) + 2
	default:
		return fmt.Errorf("unknown address type: %d", hdr[3])
	}

	discard := make([]byte, toSkip)
	_, err = io.ReadFull(conn, discard)
	return err
}

func (c *SOCKS5Client) auth(conn net.Conn, user string) error {
	up := []byte{0x01, byte(len(user))}
	up = append(up, user...)
	up = append(up, 0x00)
	if _, err := conn.Write(up); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("auth rejected: %d", resp[1])
	}
	return nil
}
