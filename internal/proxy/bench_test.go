package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// PROXY BENCHMARKS
// =============================================================================

// BenchmarkSanitizeURL measures URL sanitization cost.
func BenchmarkSanitizeURL(b *testing.B) {
	b.Run("NoQuery", func(b *testing.B) {
		u, _ := url.Parse("http://example.com/path")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sanitizeURL(u)
		}
	})

	b.Run("WithSensitiveQuery", func(b *testing.B) {
		u, _ := url.Parse("http://example.com/path?api_key=secret&name=john&token=abc")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sanitizeURL(u)
		}
	})

	b.Run("NoSensitiveQuery", func(b *testing.B) {
		u, _ := url.Parse("http://example.com/path?name=john&age=30&color=blue")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sanitizeURL(u)
		}
	})
}

// BenchmarkHeaderStripping measures the cost of header manipulation.
func BenchmarkHeaderStripping(b *testing.B) {
	headers := http.Header{
		"Content-Type":     {"application/json"},
		"X-Forwarded-For":  {"1.2.3.4"},
		"X-Real-IP":        {"1.2.3.4"},
		"Forwarded":        {"for=1.2.3.4"},
		"Via":              {"1.1 proxy"},
		"X-Client-IP":      {"1.2.3.4"},
		"CF-Connecting-IP": {"1.2.3.4"},
		"True-Client-IP":   {"1.2.3.4"},
		"Authorization":    {"Bearer token123"},
		"Accept":           {"application/json"},
		"User-Agent":       {"test/1.0"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := headers.Clone()
		h.Del("Proxy-Connection")
		h.Del("Proxy-Authorization")
		h.Del("X-Forwarded-For")
		h.Del("X-Real-IP")
		h.Del("Forwarded")
		h.Del("Via")
		h.Del("X-Client-IP")
		h.Del("CF-Connecting-IP")
		h.Del("True-Client-IP")
	}
}

// BenchmarkBufferPool measures sync.Pool efficiency.
func BenchmarkBufferPool(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bufPtr := copyBufPool.Get().(*[]byte)
			*bufPtr = (*bufPtr)[:0]
			*bufPtr = append(*bufPtr, "hello world"...)
			copyBufPool.Put(bufPtr)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 0, 32*1024)
			buf = append(buf, "hello world"...)
			_ = buf
		}
	})
}

// BenchmarkResponseParsing measures HTTP response parsing cost.
func BenchmarkResponseParsing(b *testing.B) {
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\nOK"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bufio.NewReader(strings.NewReader(response))
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkParseRetryAfter measures Retry-After header parsing cost.
func BenchmarkTriggerRotateOnError(b *testing.B) {
	b.Run("Timeout", func(b *testing.B) {
		err := fmt.Errorf("dial tcp: i/o timeout")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errStr := err.Error()
			_ = strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "no such host") ||
				strings.Contains(errStr, "connection refused")
		}
	})

	b.Run("NotNetworkError", func(b *testing.B) {
		err := fmt.Errorf("something else")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errStr := err.Error()
			_ = strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "no such host") ||
				strings.Contains(errStr, "connection refused")
		}
	})
}

// =============================================================================
// SOCKS5 BENCHMARKS
// =============================================================================

// BenchmarkSOCKS5HandshakeServer measures server-side SOCKS5 handshake.
func BenchmarkSOCKS5HandshakeServer(b *testing.B) {
	// Start mock SOCKS5 server
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
				buf := make([]byte, 2)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				nMethods := int(buf[1])
				methods := make([]byte, nMethods)
				io.ReadFull(c, methods)
				c.Write([]byte{0x05, 0x00})
				header := make([]byte, 4)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}(conn)
		}
	}()

	addr := ln.Addr().String()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			b.Fatal(err)
		}
		// Client-side SOCKS5 handshake
		conn.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		io.ReadFull(conn, resp)
		// Connect request
		conn.Write([]byte{0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50})
		reply := make([]byte, 10)
		io.ReadFull(conn, reply)
		conn.Close()
	}
}

// BenchmarkConcurrentSOCKS5 measures concurrent SOCKS5 connections.
func BenchmarkConcurrentSOCKS5(b *testing.B) {
	// Start mock SOCKS5 server
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
				buf := make([]byte, 2)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				nMethods := int(buf[1])
				methods := make([]byte, nMethods)
				io.ReadFull(c, methods)
				c.Write([]byte{0x05, 0x00})
				header := make([]byte, 4)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}(conn)
		}
	}()

	addr := ln.Addr().String()

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
					conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
					if err != nil {
						return
					}
					conn.Write([]byte{0x05, 0x01, 0x00})
					resp := make([]byte, 2)
					io.ReadFull(conn, resp)
					conn.Write([]byte{0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50})
					reply := make([]byte, 10)
					io.ReadFull(conn, reply)
					conn.Close()
				}()
			}
			wg.Wait()
		})
	}
}
