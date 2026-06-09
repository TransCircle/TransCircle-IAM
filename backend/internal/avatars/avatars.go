// Package avatars validates, stores, and serves user avatar images on the
// persistent data volume (<DataDir>/avatars/<uuid>.<ext>). The file type is
// decided by sniffing the content, never the client-supplied filename, so a
// caller cannot smuggle a path or an unexpected extension.
package avatars

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/transcircle/iam/internal/crypto"
)

// MaxBytes caps an uploaded avatar (2 MiB).
const MaxBytes = 2 << 20

// Sentinel errors the HTTP layer maps to status codes.
var (
	// ErrUnsupportedType: content is not PNG/JPEG/WebP.
	ErrUnsupportedType = errors.New("avatars: unsupported type")
	// ErrTooLarge: the upload exceeded MaxBytes.
	ErrTooLarge = errors.New("avatars: too large")
	// ErrNoFile: no "avatar" multipart field was present.
	ErrNoFile = errors.New("avatars: no file")
)

const urlPrefix = "/api/v1/avatars/"

var extByType = map[string]string{
	"image/png":  "png",
	"image/jpeg": "jpg",
	"image/webp": "webp",
}

// fileRe guards the served/cleaned filename (defense-in-depth; chi {file} can
// never contain a path separator).
var fileRe = regexp.MustCompile(`^[0-9a-fA-F-]{36}\.(png|jpe?g|webp)$`)

func avatarsDir(dataDir string) string { return filepath.Join(dataDir, "avatars") }

// PublicURL maps a stored filename to its served URL path.
func PublicURL(file string) string { return urlPrefix + file }

// Save sniffs the content type, writes the image to <dataDir>/avatars/<uuid>.<ext>
// (dir 0700, file 0600) and returns its public URL path. Returns ErrUnsupportedType
// for anything other than PNG/JPEG/WebP.
func Save(dataDir string, f multipart.File) (publicURL string, err error) {
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	ext, ok := extByType[http.DetectContentType(head[:n])]
	if !ok {
		return "", ErrUnsupportedType
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	dir := avatarsDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := crypto.NewUUIDv7().String() + "." + ext
	dst := filepath.Join(dir, name)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, f); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return "", err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return "", err
	}
	return PublicURL(name), nil
}

// SaveUpload parses the multipart "avatar" field (capped at MaxBytes), validates
// the image, and stores it. Returns the public URL or one of the sentinel errors
// (ErrTooLarge, ErrNoFile, ErrUnsupportedType) for the HTTP layer to map.
func SaveUpload(w http.ResponseWriter, r *http.Request, dataDir string) (string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBytes+(1<<16))
	if err := r.ParseMultipartForm(MaxBytes); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return "", ErrTooLarge
		}
		return "", err
	}
	file, header, err := r.FormFile("avatar")
	if err != nil {
		return "", ErrNoFile
	}
	defer file.Close()
	if header.Size > MaxBytes {
		return "", ErrTooLarge
	}
	return Save(dataDir, file)
}

// Remove best-effort deletes the file backing a public avatar URL (used to clean
// up a user's previous avatar on re-upload). Blank/foreign URLs are ignored.
func Remove(dataDir, publicURL string) {
	file := strings.TrimPrefix(publicURL, urlPrefix)
	if file == "" || file == publicURL || !fileRe.MatchString(file) {
		return
	}
	_ = os.Remove(filepath.Join(avatarsDir(dataDir), file))
}

// ServeFile validates the requested filename and streams the avatar. Returns
// false (caller should 404) for an invalid name or a missing file.
func ServeFile(w http.ResponseWriter, r *http.Request, dataDir, file string) bool {
	if !fileRe.MatchString(file) {
		return false
	}
	path := filepath.Join(avatarsDir(dataDir), file)
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		return false
	}
	w.Header().Set("Cache-Control", "private, max-age=300")
	http.ServeFile(w, r, path)
	return true
}
