package stream

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

func CopySSE(w http.ResponseWriter, body io.ReadCloser, statusCode int) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		CopyRaw(w, body)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(statusCode)
	flusher.Flush()

	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)

	for {
		n, err := body.Read(*buf)
		if n > 0 {
			if _, wErr := w.Write((*buf)[:n]); wErr != nil {
				return
			}
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}

func CopyRaw(w io.Writer, body io.ReadCloser) {
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	io.CopyBuffer(w, body, *buf)
}

// Relay copies bidirectionally between dst and src until both directions
// finish (either side closing or ctx cancellation tears down the pair),
// then closes both connections.
//
// It returns the byte counts per direction:
//
//	srcToDst: bytes copied from src into dst
//	dstToSrc: bytes copied from dst into src
//
// The counts are safe to read on return (WaitGroup provides the
// happens-before edge with the copy goroutines).
func Relay(ctx context.Context, dst io.ReadWriteCloser, src io.ReadWriteCloser) (srcToDst int64, dstToSrc int64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Close connections when context is done to abort pending blocking Read calls
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			dst.Close()
			src.Close()
		case <-done:
		}
	}()

	go func() {
		defer wg.Done()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		var err error
		srcToDst, err = io.CopyBuffer(dst, src, *buf)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		if err != nil {
			cancel()
		}
	}()

	go func() {
		defer wg.Done()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		var err error
		dstToSrc, err = io.CopyBuffer(src, dst, *buf)
		if tc, ok := src.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		if err != nil {
			cancel()
		}
	}()

	wg.Wait()
	close(done)
	dst.Close()
	src.Close()
	return srcToDst, dstToSrc
}

func HasSSEContentType(header http.Header) bool {
	return strings.Contains(header.Get("Content-Type"), "text/event-stream")
}
