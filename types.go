package epicserver

// Fields is a convenient JSON object helper for building payloads.
// Example: Fields{"ok": true, "user": u}
type Fields map[string]any

// StringFields is a string-to-string map helper (e.g., for headers or metadata).
type StringFields map[string]string

// Accounts represents username->password maps for BasicAuth style configs.
// This mirrors gin.Accounts but with an EpicServer name.
type Accounts map[string]string

// Msg is a standard message envelope: {"message": "..."}
type Msg struct {
	Message string `json:"message"`
}

// Err is a standard error envelope: {"error": "..."}
// You can include optional details for debugging or client context.
type Err struct {
	Error   string `json:"error"`
	Details any    `json:"details,omitempty"`
}

// Envelope wraps a single value under a "data" key.
// Example: Envelope[User]{Data: user}
type Envelope[T any] struct {
	Data T `json:"data"`
}

// List is a simple collection envelope: {"items": [...]}
type List[T any] struct {
	Items []T `json:"items"`
}

// Page is a paginated collection envelope commonly used for list endpoints.
// Total is optional (omit if unknown or expensive to compute).
type Page[T any] struct {
	Items   []T `json:"items"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total,omitempty"`
}
