package backend

import (
	"net"
	"time"
)

// TuneTCP configures a TCP connection for proxy use: no delay, keepalive.
// It unwraps nested net.Conn wrappers (e.g. inFlightConn, pooledConnWrap) if needed.
func TuneTCP(conn net.Conn) {
	for conn != nil {
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
			return
		}
		u, ok := conn.(interface{ Unwrap() net.Conn })
		if !ok {
			break
		}
		conn = u.Unwrap()
	}
}
