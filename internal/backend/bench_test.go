package backend

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// BACKEND BENCHMARKS
// =============================================================================

// BenchmarkCircuitSlotOperations measures per-slot operations.
func BenchmarkCircuitSlotOperations(b *testing.B) {
	b.Run("RecordSuccess", func(b *testing.B) {
		slot := &CircuitSlot{healthy: true, failThreshold: 3, anomalyThreshold: 2}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			slot.RecordSuccess()
		}
	})

	b.Run("RecordFailure", func(b *testing.B) {
		slot := &CircuitSlot{healthy: true, failThreshold: 3, anomalyThreshold: 2}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			slot.RecordFailure()
		}
	})

	b.Run("IsHealthy", func(b *testing.B) {
		slot := &CircuitSlot{healthy: true, failThreshold: 3, anomalyThreshold: 2}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			slot.IsHealthy()
		}
	})

	b.Run("ShouldRotate", func(b *testing.B) {
		slot := &CircuitSlot{healthy: true, failThreshold: 3, anomalyThreshold: 2}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			slot.ShouldRotate(50)
		}
	})

	b.Run("Reset", func(b *testing.B) {
		slot := &CircuitSlot{healthy: true, failThreshold: 3, anomalyThreshold: 2}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			slot.Reset()
		}
	})
}

// BenchmarkCryptoRandInt measures the cost of crypto/rand for random selection.
func BenchmarkCryptoRandInt(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cryptoRandInt(100)
	}
}

// BenchmarkRouterDialContext measures Router.DialContext latency.
func BenchmarkRouterDialContext(b *testing.B) {
	directBackend := NewDirectBackend(30 * time.Second)
	router := NewRouter(directBackend)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := router.DialContext(context.Background(), "tcp", "127.0.0.1:1")
		if err != nil {
			b.Skip("connection failed (expected for port 1)")
			continue
		}
		conn.Close()
	}
}

// BenchmarkRouterRoundRobin measures router round-robin selection.
func BenchmarkRouterRoundRobin(b *testing.B) {
	directBackend := NewDirectBackend(30 * time.Second)
	router := NewRouter(directBackend)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = router.current.Load()
		router.current.Store((router.current.Load() + 1) % 1)
	}
}

// BenchmarkSOCKS5Handshake measures SOCKS5 handshake cost.
func BenchmarkSOCKS5Handshake(b *testing.B) {
	// Start a mock SOCKS5 server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read greeting
				buf := make([]byte, 2)
				if _, err := readFull(c, buf); err != nil {
					return
				}
				nMethods := int(buf[1])
				methods := make([]byte, nMethods)
				readFull(c, methods)
				// Reply: no auth
				c.Write([]byte{0x05, 0x00})
				// Read connect request
				header := make([]byte, 4)
				if _, err := readFull(c, header); err != nil {
					return
				}
				// Read address
				switch header[3] {
				case 0x03: // Domain
					domainLen := make([]byte, 1)
					readFull(c, domainLen)
					domain := make([]byte, domainLen[0])
					readFull(c, domain)
					port := make([]byte, 2)
					readFull(c, port)
				}
				// Connect to target
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			b.Fatal(err)
		}
		// SOCKS5 greeting
		conn.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		readFull(conn, resp)
		// SOCKS5 connect request
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		req = append(req, byte(port>>8), byte(port&0xff))
		conn.Write(req)
		reply := make([]byte, 10)
		readFull(conn, reply)
		conn.Close()
	}
}

// BenchmarkTuneTCP measures TCP tuning cost.
func BenchmarkTuneTCP(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		conn, _ := ln.Accept()
		TuneTCP(conn)
		conn.Close()
		ln.Close()
	}
}

// BenchmarkBackendSelection measures backend selection latency.
func BenchmarkBackendSelection(b *testing.B) {
	directBackend := NewDirectBackend(30 * time.Second)
	router := NewRouter(directBackend)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate backend selection
		total := int64(len(router.backends))
		if total == 0 {
			continue
		}
		cur := router.current.Load()
		idx := (cur + 1) % total
		router.current.Store(idx)
	}
}

// BenchmarkBypassHostCheck measures bypass host matching latency.
func BenchmarkBypassHostCheck(b *testing.B) {
	directBackend := NewDirectBackend(30 * time.Second)
	router := NewRouter(directBackend)
	router.SetBypassHosts([]string{"example.com", "api.openai.com", "codebuff.com"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.isBypassHost("api.openai.com")
	}
}

// BenchmarkAnomalyReporting measures anomaly reporting latency.
func BenchmarkAnomalyReporting(b *testing.B) {
	directBackend := NewDirectBackend(30 * time.Second)
	router := NewRouter(directBackend)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.ReportAnomaly(-1)
	}
}

// =============================================================================
// HELPER
// =============================================================================

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// =============================================================================
// CONCURRENT BENCHMARKS
// =============================================================================

// BenchmarkConcurrentDialContext measures concurrent dial performance.
func BenchmarkConcurrentDialContext(b *testing.B) {
	directBackend := NewDirectBackend(30 * time.Second)
	router := NewRouter(directBackend)

	for _, concurrency := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("c%d", concurrency), func(b *testing.B) {
			var wg sync.WaitGroup
			limiter := make(chan struct{}, concurrency)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				limiter <- struct{}{}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-limiter }()
					conn, err := router.DialContext(context.Background(), "tcp", "127.0.0.1:1")
					if err != nil {
						return
					}
					conn.Close()
				}()
			}
			wg.Wait()
		})
	}
}
