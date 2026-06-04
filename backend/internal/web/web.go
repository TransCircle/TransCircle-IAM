// Package web embeds the built frontend SPA so the single binary serves both the
// API and the UI on one port. The dist/ directory holds a placeholder for local
// builds; the Docker build overwrites it with the real `frontend/dist` output
// before compiling.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// FS returns the embedded SPA filesystem rooted at the dist directory.
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("web: embed dist: " + err.Error())
	}
	return sub
}
