// Package serve runs the cavet dashboard: a loopback-only HTTP server with
// the embedded page (converted from the approved mock) and JSON endpoints
// over .cavet state and the metrics cache (serve-task-1). Reads never take
// the artefact lock; the only write is the serve-start metrics refresh.
package serve

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/ChaosChild/cavet/internal/store"
)

//go:embed assets
var assets embed.FS

// Server serves one store's dashboard.
type Server struct {
	st *store.Store
}

// New wraps a store.
func New(s *store.Store) *Server { return &Server{st: s} }

// Handler builds the route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err) // embed misconfiguration, a build-time property
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/findings/", s.handleFindingDetail)
	mux.HandleFunc("/api/items", s.handleItems)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := assets.ReadFile("assets/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b) //nolint:errcheck // best-effort body write on a broken pipe
	})
	return mux
}

// ensureMetrics recomputes a stale metrics cache under the artefact lock
// (serve-task-1 D5: precomputed at serve start, never per-request).
func ensureMetrics(s *store.Store) error {
	if !s.MetricsStale() {
		return nil
	}
	rel, err := s.Lock()
	if err != nil {
		return err
	}
	defer rel()
	if s.MetricsStale() { // re-check: a concurrent scan may have refreshed it
		if err := s.RefreshMetrics(); err != nil {
			return fmt.Errorf("metrics refresh: %w", err)
		}
	}
	return nil
}

// Run refreshes a stale metrics cache, prints the URL, and serves until
// interrupt. Loopback only, hard-coded: the dashboard has no auth, so it must
// never be reachable off-host.
func Run(s *store.Store, port int) error {
	if err := ensureMetrics(s); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("cavet serve: http://%s (loopback only; Ctrl+C to stop)\n", addr)
	srv := &http.Server{Addr: addr, Handler: New(s).Handler(), ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}
