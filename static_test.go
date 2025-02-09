package EpicServer

import (
	"embed"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

//go:embed tests
var content embed.FS

// Test WithStaticDirectory
func TestWithStaticDirectory(t *testing.T) {
	// Create a test server
	server := &Server{Engine: gin.Default()}

	// Call WithStaticDirectory with valid parameters
	WithStaticDirectory("/assets", &content, "tests")(server)

	// Make a request to the static file
	req := httptest.NewRequest(http.MethodGet, "/assets/text.txt", nil)
	resp := httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Code)
	}

	// Make a request to a non-existent file in the static directory
	req = httptest.NewRequest(http.MethodGet, "/assets/nonexistent.txt", nil)
	resp = httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusNotFound {
		t.Errorf("expected status Not Found, got %v", resp.Code)
	}
}

// Test WithStaticFile
func TestWithStaticFile(t *testing.T) {
	// Create a test server
	server := &Server{Engine: gin.Default()}

	// Call WithStaticFile with valid parameters
	WithStaticFile("/file", &content, "tests/text.txt", "text/plain")(server)

	// Make a request to the static file
	req := httptest.NewRequest(http.MethodGet, "/file", nil)
	resp := httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Code)
	}

	// Make a request to a non-existent file
	req = httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	resp = httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusNotFound {
		t.Errorf("expected status Not Found, got %v", resp.Code)
	}
}

// Test WithSPACatchAll
func TestWithSPACatchAll(t *testing.T) {
	// Create a test server
	server := &Server{Engine: gin.Default()}

	// Call WithSPACatchAll with valid parameters
	WithSPACatchAll(&content, "tests", "tests/index.html")(server)

	// Make a request to a non-existent file
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	resp := httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Code)
	}

	// Make a request to the index file
	req = httptest.NewRequest(http.MethodGet, "/index.html", nil)
	resp = httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Code)
	}
}

// Test ServeEmbededFile
func TestServeEmbededFile(t *testing.T) {
	// Create a test server
	server := &Server{Engine: gin.Default()}

	// Call ServeEmbededFile with valid parameters
	ServeEmbededFile(server, &content, "/text.txt", "tests/text.txt", "text/plain")

	// Make a request to the embedded file
	req := httptest.NewRequest(http.MethodGet, "/text.txt", nil)
	resp := httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Code)
	}

	// Make a request to a non-existent file
	req = httptest.NewRequest(http.MethodGet, "/nonexistent.txt", nil)
	resp = httptest.NewRecorder()
	server.Engine.ServeHTTP(resp, req)

	// Check the response status
	if resp.Code != http.StatusNotFound {
		t.Errorf("expected status Not Found, got %v", resp.Code)
	}
}
