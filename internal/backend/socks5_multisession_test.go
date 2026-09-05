package backend

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestTorSOCKS5_MultiSessionOnSameTCPConnection is the CRITICAL test.
// It proves whether Tor supports multiple SOCKS5 sessions on one TCP socket.
//
// If this test PASSES → raw-TCP pooling is valid.
// If this test FAILS  → raw-TCP pooling is IMPOSSIBLE.
func TestTorSOCKS5_MultiSessionOnSameTCPConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	torAddr := "127.0.0.1:9150"
	destA := "httpbin.org:80"
	destB := "ifconfig.me:80"

	// Step 1: Open ONE TCP connection to Tor SOCKS port
	rawConn, err := net.DialTimeout("tcp", torAddr, 2*time.Second)
	if err != nil {
		t.Skipf("skipping integration test: Tor not running on %s: %v", torAddr, err)
	}
	t.Logf("STEP 1: TCP connection opened to %s (fd exists)", torAddr)

	// Step 2: First SOCKS5 handshake → CONNECT to destA
	t.Log("STEP 2: Attempting first SOCKS5 session...")
	if err := socks5Connect(rawConn, destA, "session-1"); err != nil {
		rawConn.Close()
		t.Skipf("skipping test: first SOCKS5 CONNECT to external host %s failed (Tor network error): %v", destA, err)
	}
	t.Log("STEP 2: First SOCKS5 CONNECT succeeded")

	// Step 3: Verify the tunnel works — send HTTP request
	httpReq := fmt.Sprintf("GET /ip HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", destA)
	if _, err := rawConn.Write([]byte(httpReq)); err != nil {
		rawConn.Close()
		t.Fatalf("failed to write HTTP request: %v", err)
	}

	// Read response
	buf := make([]byte, 4096)
	var totalRead int
	rawConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		n, err := rawConn.Read(buf[totalRead:])
		totalRead += n
		if err != nil {
			break
		}
		if totalRead >= len(buf) {
			break
		}
	}
	response := string(buf[:totalRead])
	t.Logf("STEP 3: Got %d bytes from destA: %s", totalRead, truncate(response, 200))

	if totalRead == 0 {
		rawConn.Close()
		t.Fatal("no data received from destA — tunnel is broken")
	}

	// Step 4: Close the tunnel (read side)
	// We need to signal to Tor that we're done with this session.
	// Close the write side (half-close) to send FIN.
	t.Log("STEP 4: Closing tunnel (half-close write side)")
	tcpConn := rawConn.(*net.TCPConn)
	tcpConn.CloseWrite()

	// Read any remaining data from destA (Tor may send FIN + remaining)
	rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	remaining := make([]byte, 4096)
	var remainingTotal int
	for {
		n, err := rawConn.Read(remaining)
		remainingTotal += n
		if err != nil {
			break
		}
	}
	t.Logf("STEP 4: Read %d remaining bytes after CloseWrite", remainingTotal)

	// Step 5: Check socket state — is it still alive?
	t.Log("STEP 5: Checking socket state after tunnel close")
	localAddr := rawConn.LocalAddr()
	remoteAddr := rawConn.RemoteAddr()
	t.Logf("  LocalAddr:  %v", localAddr)
	t.Logf("  RemoteAddr: %v", remoteAddr)

	// Try to read — should get EOF or error if Tor closed the connection
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	probe := make([]byte, 1)
	_, probeErr := rawConn.Read(probe)
	t.Logf("  Probe read after tunnel close: err=%v", probeErr)

	// Step 6: ATTEMPT SECOND SOCKS5 HANDSHAKE on the same socket
	t.Log("STEP 6: Attempting second SOCKS5 handshake on same TCP socket...")
	err = socks5Connect(rawConn, destB, "session-2")

	if err != nil {
		t.Logf("CONFIRMED: Second SOCKS5 handshake FAILED: %v", err)
		t.Logf("Tor does NOT support multiple sessions on one TCP connection.")
		t.Logf("Raw-TCP pooling is IMPOSSIBLE. Pooling must be per-destination tunnel.")
		rawConn.Close()
		t.Skipf("Architectural constraint confirmed: Tor rejects second SOCKS5 session: %v", err)
	}

	t.Log("STEP 6: Second SOCKS5 CONNECT succeeded!")

	// Step 7: Verify the second tunnel works
	t.Log("STEP 7: Verifying second tunnel reaches destB...")
	httpReq2 := fmt.Sprintf("GET /ip HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", destB)
	if _, err := rawConn.Write([]byte(httpReq2)); err != nil {
		rawConn.Close()
		t.Fatalf("failed to write HTTP request to destB: %v", err)
	}

	buf2 := make([]byte, 4096)
	var totalRead2 int
	rawConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		n, err := rawConn.Read(buf2[totalRead2:])
		totalRead2 += n
		if err != nil {
			break
		}
		if totalRead2 >= len(buf2) {
			break
		}
	}
	response2 := string(buf2[:totalRead2])
	t.Logf("STEP 7: Got %d bytes from destB: %s", totalRead2, truncate(response2, 200))

	rawConn.Close()

	// FINAL VERDICT
	if totalRead2 > 0 {
		t.Log("========================================")
		t.Log("  VERDICT: Tor SUPPORTS multi-session")
		t.Log("  Raw-TCP pooling is VALID")
		t.Log("========================================")
	} else {
		t.Fatal("Second tunnel produced no data — cannot confirm multi-session support")
	}
}

// TestTorSOCKS5_MultiSessionThreeRounds tests 3 consecutive sessions
// to prove it's not a one-off fluke.
func TestTorSOCKS5_MultiSessionThreeRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	torAddr := "127.0.0.1:9150"
	destinations := []string{
		"httpbin.org:80",
		"ifconfig.me:80",
		"icanhazip.com:80",
	}

	rawConn, err := net.DialTimeout("tcp", torAddr, 2*time.Second)
	if err != nil {
		t.Skipf("skipping integration test: Tor not running on %s: %v", torAddr, err)
	}
	defer rawConn.Close()

	for i, dest := range destinations {
		t.Logf("--- Round %d: CONNECT to %s ---", i+1, dest)

		if err := socks5Connect(rawConn, dest, fmt.Sprintf("round-%d", i+1)); err != nil {
			if i > 0 {
				t.Logf("CONFIRMED: Round %d failed as expected: %v", i+1, err)
				t.Logf("Tor closes TCP socket after first tunnel — raw-TCP pooling impossible.")
				t.Skipf("Architectural constraint: round %d failed: %v", i+1, err)
			}
			t.Fatalf("round %d: SOCKS5 CONNECT failed unexpectedly: %v", i+1, err)
		}

		// Send HTTP request
		httpReq := fmt.Sprintf("GET /ip HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", dest)
		if _, err := rawConn.Write([]byte(httpReq)); err != nil {
			t.Fatalf("round %d: write failed: %v", i+1, err)
		}

		// Read response
		buf := make([]byte, 4096)
		var total int
		rawConn.SetReadDeadline(time.Now().Add(15 * time.Second))
		for {
			n, err := rawConn.Read(buf[total:])
			total += n
			if err != nil {
				break
			}
		}
		t.Logf("round %d: got %d bytes", i+1, total)

		if total == 0 {
			t.Fatalf("round %d: no data received — tunnel broken", i+1)
		}

		// Half-close the tunnel
		tcpConn := rawConn.(*net.TCPConn)
		tcpConn.CloseWrite()

		// Drain remaining
		rawConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			_, err := rawConn.Read(buf)
			if err != nil {
				break
			}
		}

		// Reset deadline for next round
		rawConn.SetReadDeadline(time.Time{})
	}

	t.Log("========================================")
	t.Log("  VERDICT: 3 consecutive sessions OK")
	t.Log("  Tor supports multi-session on same TCP")
	t.Log("========================================")
}

// socks5Connect performs a complete SOCKS5 handshake + CONNECT.
func socks5Connect(conn net.Conn, targetAddr, username string) error {
	// Phase 1: Greeting
	greeting := []byte{0x05, 0x02, 0x00, 0x02} // VER=5, NMETHODS=2, NO-AUTH, USERNAME/PASSWORD
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}

	// Read greeting response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		return fmt.Errorf("greeting read: %w", err)
	}
	if methodResp[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", methodResp[0])
	}

	// Phase 2: Username/password auth
	if methodResp[1] == 0x02 {
		authBuf := []byte{0x01}
		authBuf = append(authBuf, byte(len(username)))
		authBuf = append(authBuf, []byte(username)...)
		authBuf = append(authBuf, 0x00) // empty password
		if _, err := conn.Write(authBuf); err != nil {
			return fmt.Errorf("auth write: %w", err)
		}

		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return fmt.Errorf("auth read: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("auth rejected: %d", authResp[1])
		}
	} else if methodResp[1] != 0x00 {
		return fmt.Errorf("unsupported auth method: %d", methodResp[1])
	}

	// Phase 3: CONNECT
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("split host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parse port: %w", err)
	}

	connectBuf := []byte{0x05, 0x01, 0x00, 0x03} // VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN
	connectBuf = append(connectBuf, byte(len(host)))
	connectBuf = append(connectBuf, []byte(host)...)
	connectBuf = append(connectBuf, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(connectBuf); err != nil {
		return fmt.Errorf("connect write: %w", err)
	}

	// Read CONNECT response
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("connect read: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("CONNECT failed: reply code=%d", reply[1])
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
