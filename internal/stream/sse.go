package stream

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
)

var eventPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 4096)
		return &buf
	},
}

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

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)

	for scanner.Scan() {
		event := scanner.Bytes()

		bufPtr := eventPool.Get().(*[]byte)
		*bufPtr = append((*bufPtr)[:0], event...)
		*bufPtr = append(*bufPtr, '\n', '\n')
		if _, err := w.Write(*bufPtr); err != nil {
			eventPool.Put(bufPtr)
			return
		}
		eventPool.Put(bufPtr)

		flusher.Flush()
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
