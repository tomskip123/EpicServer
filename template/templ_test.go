package template

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// MockTemplComponent implements the templ.Component interface for testing
type MockTemplComponent struct{}

func (m *MockTemplComponent) Render(ctx context.Context, w io.Writer) error {
	_, err := w.Write([]byte("<div>Mock Template</div>"))
	return err
}

// ErrorComponent is a component that returns an error when rendered
type ErrorComponent struct{}

func (e *ErrorComponent) Render(ctx context.Context, w io.Writer) error {
	return assert.AnError
}

// Test the TemplRender function
func TestTemplRender(t *testing.T) {
	// Set up Gin in test mode
	gin.SetMode(gin.TestMode)

	// Create a test component
	component := &MockTemplComponent{}

	// Create a Gin test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	// Call the function being tested
	err := TemplRender(c, http.StatusOK, component)

	// Verify results
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<div>Mock Template</div>", w.Body.String())
}

// Test error handling in TemplRender
func TestTemplRenderWithError(t *testing.T) {
	// Set up Gin in test mode
	gin.SetMode(gin.TestMode)

	// Create a test component that returns an error
	errComponent := &ErrorComponent{}

	// Create a Gin test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	// Call the function being tested
	err := TemplRender(c, http.StatusOK, errComponent)

	// Verify results
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	assert.Equal(t, http.StatusOK, w.Code) // Status should still be set
	assert.Empty(t, w.Body.String())       // Body should be empty due to error
}
