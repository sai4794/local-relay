package stream

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// STREAM BENCHMARKS
// =============================================================================

// BenchmarkRelay measures bidirectional relay throughput.
func BenchmarkRelay(b *testing.B) {
	b.Run("SmallPayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r1, w1 := io.Pipe()
			r2, w2 := io.Pipe()

			// Writer goroutine
			go func() {
				w1.Write([]byte("hello"))
				w1.Close()
			}()

			// Relay
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			Relay(ctx, &mockConn{r1, w2, nil}, &mockConn{r2, w1, nil})
		}
	})

	b.Run("LargePayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r1, w1 := io.Pipe()
			r2, w2 := io.Pipe()

			// Writer goroutine
			go func() {
				data := strings.Repeat("A", 1024*1024) // 1MB
				w1.Write([]byte(data))
				w1.Close()
			}()

			// Relay
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			Relay(ctx, &mockConn{r1, w2, nil}, &mockConn{r2, w1, nil})
		}
	})
}

// BenchmarkRelayConcurrent measures relay throughput under concurrent load.
func BenchmarkRelayConcurrent(b *testing.B) {
	for _, concurrency := range []int{1, 10, 50} {
		b.Run(concurrencyName(concurrency), func(b *testing.B) {
			var wg sync.WaitGroup
			limiter := make(chan struct{}, concurrency)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				limiter <- struct{}{}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-limiter }()
					r1, w1 := io.Pipe()
					r2, w2 := io.Pipe()

					go func() {
						w1.Write([]byte("hello"))
						w1.Close()
					}()

					ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
					defer cancel()
					Relay(ctx, &mockConn{r1, w2, nil}, &mockConn{r2, w1, nil})
				}()
			}
			wg.Wait()
		})
	}
}

// BenchmarkCopySSE measures SSE copy performance.
func BenchmarkCopySSE(b *testing.B) {
	b.Run("WithFlusher", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := &mockResponseWriter{headers: make(map[string][]string)}
			body := io.NopCloser(strings.NewReader("data: test\n\n"))
			CopySSE(w, body, 200)
		}
	})

	b.Run("WithoutFlusher", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := &mockWriter{}
			body := io.NopCloser(strings.NewReader("data: test\n\n"))
			CopyRaw(w, body)
		}
	})
}

// BenchmarkCopyRaw measures raw copy performance.
func BenchmarkCopyRaw(b *testing.B) {
	b.Run("SmallPayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := &mockWriter{}
			body := io.NopCloser(strings.NewReader("hello"))
			CopyRaw(w, body)
		}
	})

	b.Run("LargePayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := &mockWriter{}
			data := strings.Repeat("A", 1024*1024) // 1MB
			body := io.NopCloser(strings.NewReader(data))
			CopyRaw(w, body)
		}
	})
}

// BenchmarkHasSSEContentType measures content-type check cost.
func BenchmarkHasSSEContentType(b *testing.B) {
	b.Run("SSE", func(b *testing.B) {
		header := map[string][]string{"Content-Type": {"text/event-stream"}}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			HasSSEContentType(header)
		}
	})

	b.Run("NotSSE", func(b *testing.B) {
		header := map[string][]string{"Content-Type": {"application/json"}}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			HasSSEContentType(header)
		}
	})
}

// BenchmarkRelayThroughNet tests relay with real TCP connections.
func BenchmarkRelayThroughNet(b *testing.B) {
	// Start echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Client side
		clientConn, serverConn := net.Pipe()

		// Connect to echo server
		echoConn, _ := net.Dial("tcp", echoLn.Addr().String())

		// Write data
		go func() {
			clientConn.Write([]byte("hello"))
			clientConn.Close()
		}()

		// Relay
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		Relay(ctx, echoConn, serverConn)
	}
}

// =============================================================================
// HELPERS
// =============================================================================

type mockConn struct {
	io.Reader
	io.Writer
	io.Closer
}

func (c *mockConn) Read(p []byte) (int, error)  { return c.Reader.Read(p) }
func (c *mockConn) Write(p []byte) (int, error) { return c.Writer.Write(p) }
func (c *mockConn) Close() error                { return c.Closer.Close() }

type mockWriter struct {
	data []byte
}

func (w *mockWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

type mockResponseWriter struct {
	headers map[string][]string
	code    int
}

func (w *mockResponseWriter) Header() http.Header         { return w.headers }
func (w *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *mockResponseWriter) WriteHeader(code int)        { w.code = code }
func (w *mockResponseWriter) Flush()                      {}

func concurrencyName(n int) string {
	return fmt.Sprintf("c%d", n)
}
