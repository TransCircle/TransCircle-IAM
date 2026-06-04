package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/web"
)

// apiPrefixes are backend-owned path prefixes. Unmatched routes under these
// return a JSON 404 instead of the SPA index (so API clients get proper errors).
var apiPrefixes = []string{"/api/", "/oauth2/", "/.well-known/", "/healthz", "/readyz", "/version", "/metrics"}

// spaHandler serves the embedded frontend with HTML5 history fallback. Real
// static assets stream through the file server; unknown routes and index.html
// are written directly to avoid the file server's canonical 301 redirect.
func spaHandler() http.HandlerFunc {
	fsys := web.FS()
	fileServer := http.FileServerFS(fsys)
	indexBytes, _ := fs.ReadFile(fsys, "index.html")

	serveIndex := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexBytes)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		for _, p := range apiPrefixes {
			if r.URL.Path == p || strings.HasPrefix(r.URL.Path, p) {
				httpx.Error(w, r, httpx.ErrNotFound)
				return
			}
		}
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "" || clean == "index.html" {
			serveIndex(w)
			return
		}
		if st, err := fs.Stat(fsys, clean); err != nil || st.IsDir() {
			// Unknown path → SPA client-side route.
			serveIndex(w)
			return
		}
		fileServer.ServeHTTP(w, r)
	}
}
