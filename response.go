package epicserver

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "path/filepath"
    "time"
)

// H is a shorthand for JSON objects.
type H map[string]any

// JSON writes v as JSON with the provided HTTP status code.
// It sets Content-Type and X-Content-Type-Options headers.
func JSON(w http.ResponseWriter, status int, v any) error {
    var buf bytes.Buffer
    enc := json.NewEncoder(&buf)
    if err := enc.Encode(v); err != nil {
        return err
    }
    h := w.Header()
    h.Set("Content-Type", "application/json; charset=utf-8")
    h.Set("X-Content-Type-Options", "nosniff")
    w.WriteHeader(status)
    _, err := w.Write(buf.Bytes())
    return err
}

// ErrorJSON writes a standardized JSON error body with status code.
func ErrorJSON(w http.ResponseWriter, status int, message string) error {
    return JSON(w, status, H{"error": message})
}

// HTML writes an HTML response body with the provided status code.
func HTML(w http.ResponseWriter, status int, html string) error {
    h := w.Header()
    h.Set("Content-Type", "text/html; charset=utf-8")
    h.Set("X-Content-Type-Options", "nosniff")
    w.WriteHeader(status)
    _, err := io.WriteString(w, html)
    return err
}

// Text writes a plain text response with the provided status code.
func Text(w http.ResponseWriter, status int, text string) error {
    h := w.Header()
    h.Set("Content-Type", "text/plain; charset=utf-8")
    h.Set("X-Content-Type-Options", "nosniff")
    w.WriteHeader(status)
    _, err := io.WriteString(w, text)
    return err
}

// Bytes writes raw bytes with an explicit content type and status.
func Bytes(w http.ResponseWriter, status int, contentType string, data []byte) error {
    h := w.Header()
    if contentType != "" {
        h.Set("Content-Type", contentType)
    }
    h.Set("X-Content-Type-Options", "nosniff")
    w.WriteHeader(status)
    _, err := w.Write(data)
    return err
}

// Stream copies from r to the response with contentType and status.
func Stream(w http.ResponseWriter, status int, contentType string, r io.Reader) error {
    h := w.Header()
    if contentType != "" {
        h.Set("Content-Type", contentType)
    }
    h.Set("X-Content-Type-Options", "nosniff")
    w.WriteHeader(status)
    _, err := io.Copy(w, r)
    return err
}

// File serves a file from disk using http.ServeFile.
func File(w http.ResponseWriter, r *http.Request, filePath string) {
    http.ServeFile(w, r, filePath)
}

// Download serves a file and forces a download with the given filename.
func Download(w http.ResponseWriter, r *http.Request, filePath string, downloadName string) {
    if downloadName == "" {
        downloadName = filepath.Base(filePath)
    }
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", downloadName))
    http.ServeFile(w, r, filePath)
}

// Redirect sends an HTTP redirect with the provided status code.
func Redirect(w http.ResponseWriter, r *http.Request, location string, status int) {
    http.Redirect(w, r, location, status)
}

// NoContent sends a 204 No Content with no body.
func NoContent(w http.ResponseWriter) {
    w.WriteHeader(http.StatusNoContent)
}

// SetCookie sets a cookie on the response.
func SetCookie(w http.ResponseWriter, c *http.Cookie) { //nolint: revive // convenience wrapper
    http.SetCookie(w, c)
}

// ClearCookie deletes a cookie by setting it expired.
func ClearCookie(w http.ResponseWriter, name string, path string, domain string) {
    if path == "" {
        path = "/"
    }
    http.SetCookie(w, &http.Cookie{
        Name:     name,
        Value:    "",
        Path:     path,
        Domain:   domain,
        MaxAge:   -1,
        Expires:  time.Unix(0, 0),
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
    })
}

