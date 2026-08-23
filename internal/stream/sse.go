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

func Relay(ctx context.Context, dst io.ReadWriteCloser, src io.ReadWriteCloser) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer cancel()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		io.CopyBuffer(dst, src, *buf)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		io.CopyBuffer(src, dst, *buf)
		if tc, ok := src.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	dst.Close()
	src.Close()
}

func HasSSEContentType(header http.Header) bool {
	return strings.Contains(header.Get("Content-Type"), "text/event-stream")
}
