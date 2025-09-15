package epicserver

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// DefaultMaxBodyBytes is the default limit for request body reads in helpers.
const DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

// BindJSON reads and decodes JSON from the request body into dst with a sane size limit.
// It accepts standard and "+json" content types.
func BindJSON(r *http.Request, dst any) error {
	return BindJSONWithLimit(r, dst, DefaultMaxBodyBytes)
}

// BindJSONStrict is like BindJSON but disallows unknown fields and extra data.
func BindJSONStrict(r *http.Request, dst any) error {
	return BindJSONStrictWithLimit(r, dst, DefaultMaxBodyBytes)
}

// BindJSONWithLimit decodes JSON with an explicit size limit.
func BindJSONWithLimit(r *http.Request, dst any, maxBytes int64) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		return errors.New("unsupported Content-Type; expected application/json")
	}
	lr := io.LimitReader(r.Body, maxBytes)
	dec := json.NewDecoder(lr)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

// BindJSONStrictWithLimit decodes JSON with an explicit size limit, disallowing unknown fields
// and ensuring there is no trailing data.
func BindJSONStrictWithLimit(r *http.Request, dst any, maxBytes int64) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		return errors.New("unsupported Content-Type; expected application/json")
	}
	lr := io.LimitReader(r.Body, maxBytes)
	dec := json.NewDecoder(lr)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// ensure single JSON value only
	if dec.More() {
		return errors.New("unexpected data after JSON value")
	}
	return nil
}

// ReadBody reads up to maxBytes from the request body and returns it.
func ReadBody(r *http.Request, maxBytes int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, maxBytes))
}

// BodyText reads the body as a string up to maxBytes.
func BodyText(r *http.Request, maxBytes int64) (string, error) {
	b, err := ReadBody(r, maxBytes)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Query returns the first query value for key, or empty string.
func Query(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// QueryDefault returns the first query value for key, or def if missing.
func QueryDefault(r *http.Request, key, def string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	return def
}

// QueryAll returns all query values for key.
func QueryAll(r *http.Request, key string) []string {
	return r.URL.Query()[key]
}

// QueryInt parses an int query param, returning def if missing or invalid.
func QueryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// QueryBool parses a boolean query param, returning def if missing or invalid.
// Accepts: 1, t, true, yes, on (case-insensitive) for true; 0, f, false, no, off for false.
func QueryBool(r *http.Request, key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(r.URL.Query().Get(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "t", "true", "yes", "on":
		return true
	case "0", "f", "false", "no", "off":
		return false
	default:
		return def
	}
}

// Header returns the named header value or empty string.
func Header(r *http.Request, key string) string {
	return r.Header.Get(key)
}

// HasHeader reports whether the request includes the given header.
func HasHeader(r *http.Request, key string) bool {
	_, ok := r.Header[http.CanonicalHeaderKey(key)]
	return ok
}

// BearerToken extracts the bearer token from Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	v := r.Header.Get("Authorization")
	if v == "" {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(v), "bearer ") {
		return "", false
	}
	token := strings.TrimSpace(v[len("Bearer "):])
	if token == "" {
		return "", false
	}
	return token, true
}

// ContentType returns the request Content-Type (without parameters) in lowercase.
func ContentType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// IsJSON reports whether the request Content-Type is JSON or "+json".
func IsJSON(r *http.Request) bool {
	return isJSONContentType(r.Header.Get("Content-Type"))
}

// ClientIP returns the best-effort client IP string.
// Note: Do not trust this in security decisions without validating proxy headers.
func ClientIP(r *http.Request) string {
	// X-Forwarded-For may contain multiple IPs, left-most is original client
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isJSONContentType reports whether ct is application/json or a "+json" media type.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return true // be permissive when header missing
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}
