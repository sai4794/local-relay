package backend

import (
	"net"
	"time"
)

// TuneTCP configures a TCP connection for proxy use: no delay, keepalive.
func TuneTCP(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
}
