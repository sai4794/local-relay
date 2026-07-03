package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/rotate"
	"github.com/local-relay/proxy/internal/security"
	"github.com/local-relay/proxy/internal/stream"
)

// AuthCheck is a function that checks if a username/password combo is valid.
type AuthCheck func(username, password string) bool

type SOCKS5Proxy struct {
	router       *backend.Router
	firewall     *security.Firewall
	rotator      *rotate.Rotator
	logger       *slog.Logger
	listener     net.Listener
	authCheck    AuthCheck
}

func NewSOCKS5Proxy(router *backend.Router, fw *security.Firewall, rotator *rotate.Rotator, logger *slog.Logger, authCheck AuthCheck) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		router:    router,
		firewall:  fw,
		rotator:   rotator,
		logger:    logger,
		authCheck: authCheck,
	}
}

func (p *SOCKS5Proxy) Start(addr string) error {
	var err error
	p.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	p.logger.Info("SOCKS5 proxy listening", "addr", addr)

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				p.logger.Error("SOCKS5 accept temporary error", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return nil
		}
		go p.handleConn(conn)
	}
}

func (p *SOCKS5Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	backend.TuneTCP(conn)

	if err := p.handshake(conn); err != nil {
		p.logger.Debug("SOCKS5 handshake failed", "error", err)
		return
	}

	p.recordRotation()

	target, cmd, err := p.readRequest(conn)
	if err != nil {
		p.logger.Debug("SOCKS5 request read failed", "error", err)
		return
	}

	switch cmd {
	case 0x01: // CONNECT
		p.handleConnect(conn, target)
	case 0x03: // UDP ASSOCIATE
		p.handleUDPAssociate(conn)
	default:
		p.sendReply(conn, 0x07, nil)
	}
}

func (p *SOCKS5Proxy) handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// If auth is required, offer both no-auth and user/pass
	if p.authCheck != nil {
		// Check if client supports user/pass auth (0x02)
		for _, m := range methods {
			if m == 0x02 {
				if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
					return err
				}
				return p.authenticate(conn)
			}
		}
		// Client doesn't support user/pass — reject
		_, err := conn.Write([]byte{0x05, 0xFF})
		return err
	}

	// No auth required
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func (p *SOCKS5Proxy) authenticate(conn net.Conn) error {
	// RFC 1929: version(1) + ulen(1) + uname(ulen) + plen(1) + passwd(plen)
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", hdr[0])
	}
	ulen := int(hdr[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	var plenByte [1]byte
	if _, err := io.ReadFull(conn, plenByte[:]); err != nil {
		return err
	}
	plen := int(plenByte[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	username := string(uname)
	password := string(passwd)

	if p.authCheck != nil && p.authCheck(username, password) {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}
	_, _ = conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("SOCKS5 auth failed")
}

func (p *SOCKS5Proxy) readRequest(conn net.Conn) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}

	if header[0] != 0x05 {
		return "", 0, fmt.Errorf("invalid version")
	}

	cmd := header[1]

	var target string
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", 0, err
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3], uint16(port[0])<<8|uint16(port[1]))

	case 0x03: // Domain
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return "", 0, err
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", 0, err
		}
		target = fmt.Sprintf("%s:%d", string(domain), uint16(port[0])<<8|uint16(port[1]))

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", 0, err
		}
		target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			addr[0:2], addr[2:4], addr[4:6], addr[6:8],
			addr[8:10], addr[10:12], addr[12:14], addr[14:16],
			uint16(port[0])<<8|uint16(port[1]))

	default:
		return "", 0, fmt.Errorf("unsupported address type: %d", header[3])
	}

	return target, cmd, nil
}

func (p *SOCKS5Proxy) handleConnect(conn net.Conn, target string) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		p.sendReply(conn, 0x01, nil)
		return
	}

	if p.firewall != nil && !p.firewall.AllowHost(host) {
		p.logger.Warn("blocked SOCKS5 connection to private/internal IP", "host", host)
		p.sendReply(conn, 0x02, nil)
		return
	}

	// Use request context so client disconnect can cancel the relay
	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()

	dialCtx, dialCancel := context.WithTimeout(relayCtx, 30*time.Second)
	defer dialCancel()

	destConn, err := p.router.DialContext(dialCtx, "tcp", target)
	if err != nil {
		p.logger.Error("SOCKS5 dial failed", "target", target, "error", err)

		if p.rotator != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "connection refused") ||
				strings.Contains(errStr, "connection reset") ||
				strings.Contains(errStr, "no healthy proxy") {
				p.logger.Warn("SOCKS5 dial failure, triggering rotation", "target", target)
				p.rotator.ForceRotate()
			}
		}
		p.sendReply(conn, 0x05, nil)
		return
	}

	localAddr := destConn.LocalAddr()
	tcpAddr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		p.sendReply(conn, 0x01, nil)
		destConn.Close()
		p.logger.Error("SOCKS5 local addr is not TCP", "type", fmt.Sprintf("%T", localAddr))
		return
	}
	p.sendReply(conn, 0x00, tcpAddr.IP)

	p.logger.Info("SOCKS5 CONNECT established", "target", target)

	// Use relayCtx so client disconnect cancels the relay
	stream.Relay(relayCtx, destConn, conn)
}

func (p *SOCKS5Proxy) handleUDPAssociate(conn net.Conn) {
	p.logger.Debug("UDP ASSOCIATE requested (not supported)")
	p.sendReply(conn, 0x07, nil)
}

func (p *SOCKS5Proxy) sendReply(conn net.Conn, status byte, bindIP net.IP) {
	reply := []byte{0x05, status, 0x00, 0x01}

	if bindIP == nil {
		bindIP = net.IPv4(0, 0, 0, 0)
	}

	if bindIP4 := bindIP.To4(); bindIP4 != nil {
		reply = append(reply, bindIP4...)
	} else {
		reply[3] = 0x04
		reply = append(reply, bindIP.To16()...)
	}

	reply = append(reply, 0x00, 0x00)
	conn.Write(reply)
}

func (p *SOCKS5Proxy) Stop() {
	if p.listener != nil {
		p.listener.Close()
	}
}

func (p *SOCKS5Proxy) recordRotation() {
	if p.rotator != nil && p.rotator.ShouldRotate() {
		p.logger.Info("IP rotation triggered by request count")
	}
}
