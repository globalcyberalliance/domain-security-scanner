package http

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/klauspost/compress/zstd"
)

type responseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w responseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (s *Server) handleRequestCompression(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoding := r.Header.Get("Content-Encoding")
		switch encoding {
		case "gzip":
			gzipReader, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to create gzip reader: %v", err), http.StatusBadRequest)
				return
			}
			defer gzipReader.Close()

			r.Body = gzipReader
		case "zstd":
			zstdReader, err := zstd.NewReader(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to create zstd reader: %v", err), http.StatusBadRequest)
				return
			}
			defer zstdReader.Close()

			r.Body = zstdReader.IOReadCloser()
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleResponseCompression(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prioritize ZSTD over GZIP.
		if strings.Contains(r.Header.Get("Accept-Encoding"), "zstd") {
			w.Header().Set("Content-Encoding", "zstd")

			zstdWriter, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to create zstd writer: %v", err), http.StatusInternalServerError)
				return
			}
			defer zstdWriter.Close()

			next.ServeHTTP(responseWriter{Writer: zstdWriter, ResponseWriter: w}, r)
			return
		} else if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gzipWriter := gzip.NewWriter(w)
			defer gzipWriter.Close()

			next.ServeHTTP(responseWriter{Writer: gzipWriter, ResponseWriter: w}, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLogging() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedWriter := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			if strings.HasPrefix(r.URL.Path, "/api") {
				startTime := time.Now()

				defer func() {
					if rec := recover(); rec != nil {
						s.logger.Error().
							Interface("recover info", rec).
							Bytes("debug stack", debug.Stack()).
							Msg("HTTP panic")
						http.Error(wrappedWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					}

					uri := r.URL.Path
					if query := r.URL.Query().Encode(); query != "" {
						uri += "?" + query
					}

					logWithLevel := s.logger.Info()
					if wrappedWriter.Status() >= 400 {
						logWithLevel = s.logger.Warn()
					}

					logWithLevel.
						Str("ip", r.RemoteAddr).
						Str("method", r.Method).
						Str("uri", uri).
						Int("status", wrappedWriter.Status()).
						Int64("latency", time.Since(startTime).Round(time.Millisecond).Milliseconds()).
						Msg("HTTP request")
				}()
			}

			next.ServeHTTP(wrappedWriter, r)
		})
	}
}
