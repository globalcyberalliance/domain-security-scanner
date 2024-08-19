package http

import (
	"context"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/scanner"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

// Server represents the HTTP server.
type Server struct {
	apiPath string
	logger  zerolog.Logger
	router  huma.API
	timeout time.Duration

	Addr     string
	CheckTLS bool

	// Services used by the various HTTP routes
	Advisor *scanner.Advisor
	Scanner *scanner.Scanner
}

// NewServer returns a new instance of Server.
func NewServer(logger zerolog.Logger, timeout time.Duration, version string) *Server {
	server := Server{
		apiPath: "/api/v1",
		logger:  logger,
		timeout: timeout,
	}

	config := huma.DefaultConfig("Domain Security Scanner", version)
	config.Info.Description = "The Domain Security Scanner can be used to perform scans against domains for DKIM, DMARC, and SPF DNS records. You can also serve this functionality via an API, or a dedicated mailbox. A web application is also available if organizations would like to perform a single domain scan for DKIM, DMARC or SPF at https://dmarcguide.globalcyberalliance.org."
	config.DocsPath = "" // disable Huma's Stoplight handler
	config.OpenAPIPath = "/api/v1/docs"

	mux := chi.NewMux()
	mux.Use(middleware.RedirectSlashes, middleware.RealIP, handleLogging(&logger), middleware.Recoverer)
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	mux.Use(httprate.Limit(5, 3*time.Second,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			response, err := json.Marshal(huma.Error429TooManyRequests("try again later"))
			if err != nil {
				http.Error(w, "an error occurred", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(429)
			if _, err = w.Write(response); err != nil {
				return
			}
		}),
	))
	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		// redirect to the API docs
		http.Redirect(w, r, server.apiPath+"/docs", http.StatusFound)
	})
	mux.Handle("/api/v1/version", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"version":"` + version + `"}`)); err != nil {
			return
		}
	}))

	server.router = humachi.New(mux, config)
	server.router.Adapter().Handle(&huma.Operation{
		Method: http.MethodGet,
		Path:   server.apiPath + "/docs",
	}, func(ctx huma.Context) {
		ctx.SetHeader("Content-Type", "text/html")
		if _, err := ctx.BodyWriter().Write([]byte(`<!doctype html><html lang="en"><head><title>Domain Security Scanner - API Reference</title><meta charset="utf-8"><meta content="width=device-width,initial-scale=1" name="viewport"></head><body><script data-url="` + server.apiPath + `/docs.json" id="api-reference"></script><script>let apiReference = document.getElementById("api-reference")</script><script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script></body></html>`)); err != nil {
			server.logger.Error().Err(err).Msg("an error occurred while serving the API documentation")
		}
	})
	server.registerVersionRoute(version)
	server.registerScanRoutes()

	return &server
}

func (s *Server) Serve(port int) {
	if port == 0 {
		port = 8080
	}

	portString := cast.ToString(port)
	httpServer := &http.Server{
		Addr:         "0.0.0.0:" + portString,
		Handler:      s.router.Adapter(),
		WriteTimeout: 4 * s.timeout, // timeout is used by the scanner per request, so multiply it by 4 to allow for bulk requests
	}

	s.logger.Info().Msg("Starting api server on port " + portString)
	s.logger.Fatal().Err(httpServer.ListenAndServe()).Msg("an error occurred while hosting the api server")
}

func (s *Server) registerVersionRoute(version string) {
	type VersionResponse struct {
		Body struct {
			Version string `json:"version" doc:"The version of the API." example:"3.0.0"`
		}
	}

	huma.Register(s.router, huma.Operation{
		OperationID: "version",
		Summary:     "Get the version of the API",
		Method:      http.MethodGet,
		Path:        s.apiPath + "/version",
		Tags:        []string{"Version"},
	}, func(ctx context.Context, input *struct{}) (*VersionResponse, error) {
		resp := VersionResponse{}
		resp.Body.Version = version
		return &resp, nil
	})
}

func handleLogging(logger *zerolog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedWriter := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			startTime := time.Now()

			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().
						Str("type", "error").
						Timestamp().
						Interface("recover_info", rec).
						Bytes("debug_stack", debug.Stack()).
						Msg("system error")
					http.Error(wrappedWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}

				logger.Info().
					Timestamp().
					Fields(map[string]interface{}{
						"ip":      r.RemoteAddr,
						"method":  r.Method,
						"url":     r.URL.Path,
						"status":  wrappedWriter.Status(),
						"latency": time.Since(startTime).Round(time.Millisecond).String(),
					}).Msg("request")
			}()

			next.ServeHTTP(wrappedWriter, r)
		})
	}
}
