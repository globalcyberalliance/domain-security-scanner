package http

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/advisor"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/scanner"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

const DefaultRateLimit = 5

// Server represents the HTTP server.
type Server struct {
	apiPath string
	logger  zerolog.Logger
	router  huma.API
	timeout time.Duration

	Addr     string
	CheckTLS bool

	// Services used by the various HTTP routes.
	Advisor *advisor.Advisor
	Scanner *scanner.Scanner
}

// NewServer returns a new instance of Server.
func NewServer(logger zerolog.Logger, timeout time.Duration, rateLimit int, version string) *Server {
	server := Server{
		apiPath: "/api/v1",
		logger:  logger,
		timeout: timeout,
	}

	config := huma.DefaultConfig("Domain Security Scanner", version)
	config.CreateHooks = nil
	config.Info.Description = "The Domain Security Scanner can be used to perform scans against domains for DKIM, DMARC, and SPF DNS records. You can also serve this functionality via an API, or a dedicated mailbox. A web application is also available if organizations would like to perform a single domain scan for DKIM, DMARC or SPF at https://dmarcguide.globalcyberalliance.org."
	config.DocsPath = "" // Disable Huma's Stoplight handler.
	config.OpenAPIPath = "/api/v1/docs"

	if rateLimit <= 0 {
		rateLimit = DefaultRateLimit
	}

	mux := chi.NewMux()
	mux.Use(middleware.RedirectSlashes, middleware.RealIP, server.handleLogging(), server.handleRequestCompression, server.handleResponseCompression, middleware.Recoverer)
	mux.Use(cors.Handler(cors.Options{
		AllowCredentials: false,
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-CSRF-Token"},
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		ExposedHeaders:   []string{"Link"},
		MaxAge:           300, // The maximum value not ignored by any of the major browsers.
	}))
	mux.Use(httprate.Limit(rateLimit, 3*time.Second,
		httprate.WithLimitHandler(func(w http.ResponseWriter, _ *http.Request) {
			response, err := json.Marshal(huma.Error429TooManyRequests("try again later"))
			if err != nil {
				http.Error(w, "an error occurred", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			if _, err = w.Write(response); err != nil {
				return
			}
		}),
	))
	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to the API docs.
		http.Redirect(w, r, server.apiPath+"/docs", http.StatusFound)
	})
	mux.Handle("/api/v1/version", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
			server.logger.Error().Err(err).Msg("An error occurred while serving the API documentation")
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

	var (
		idleTimeout       = s.timeout
		readHeaderTimeout = s.timeout
		readTimeout       = s.timeout * 4
		writeTimeout      = s.timeout * 4
	)

	portString := cast.ToString(port)
	httpServer := &http.Server{
		Addr:              "0.0.0.0:" + portString,
		ErrorLog:          log.New(&httpLogger{s.logger}, "", 0),
		Handler:           s.router.Adapter(),
		IdleTimeout:       idleTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
	}

	s.logger.Info().Msg("Starting api server on port " + portString)
	s.logger.Fatal().Err(httpServer.ListenAndServe()).Msg("An error occurred while hosting the api server")
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
	}, func(_ context.Context, _ *struct{}) (*VersionResponse, error) {
		resp := VersionResponse{}
		resp.Body.Version = version
		return &resp, nil
	})
}

// httpLogger satisfies the http.Server.ErrorLog interface, and adapts it to use our global zerolog logger.
type httpLogger struct {
	logger zerolog.Logger
}

func (l *httpLogger) Write(p []byte) (int, error) {
	l.logger.Debug().Msg(string(p))
	return len(p), nil
}
