package EpicServer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// MockAuthHooks implements the AuthenticationHooks interface for testing
type MockAuthHooks struct {
	PreAuthCalled   bool
	PostAuthCalled  bool
	PreLoginCalled  bool
	PostLoginCalled bool
	LogoutCalled    bool
	TestUser        Claims
}

// Implement the AuthenticationHooks interface
func (m *MockAuthHooks) OnUserCreate(user Claims) (string, error) {
	return user.UserID, nil
}

func (m *MockAuthHooks) GetUserOrCreate(user Claims) (*CookieContents, error) {
	m.PreAuthCalled = true
	m.TestUser = user
	return &CookieContents{
		Email:      user.Email,
		UserId:     user.UserID,
		IsLoggedIn: true,
	}, nil
}

func (m *MockAuthHooks) OnAuthenticate(username, password string, state OAuthState) (bool, error) {
	m.PostAuthCalled = true
	return true, nil
}

func (m *MockAuthHooks) OnUserGet(userID string) (any, error) {
	m.PreLoginCalled = true
	return m.TestUser, nil
}

func (m *MockAuthHooks) OnSessionValidate(sessionToken *CookieContents) (interface{}, error) {
	m.PostLoginCalled = true
	return m.TestUser, nil
}

func (m *MockAuthHooks) OnSessionCreate(userID string) (string, error) {
	return "test-session-id", nil
}

func (m *MockAuthHooks) OnSessionDestroy(sessionToken string) error {
	m.LogoutCalled = true
	return nil
}

func (m *MockAuthHooks) OnOAuthCallbackSuccess(ctx *gin.Context, state OAuthState) error {
	return nil
}

// Test hooks integration with authentication
func TestHooks_Auth(t *testing.T) {
	// Create a new server with default options and a secret key
	server := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	// Create test authentication hooks
	mockHooks := &MockAuthHooks{
		TestUser: Claims{
			Email:  "test@example.com",
			UserID: "123",
			Role:   "user",
		},
	}

	// Set up hooks
	server.UpdateAppLayer([]AppLayer{WithAuthHooks(mockHooks)})

	// Create a test HTTP request and context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest("GET", "/test", nil)
	c.Request = req

	// Test GetUserOrCreate hook
	cookieContents, err := mockHooks.GetUserOrCreate(mockHooks.TestUser)
	assert.NoError(t, err)
	assert.True(t, mockHooks.PreAuthCalled)
	assert.Equal(t, mockHooks.TestUser.Email, cookieContents.Email)
	assert.Equal(t, mockHooks.TestUser.UserID, cookieContents.UserId)
	assert.True(t, cookieContents.IsLoggedIn)

	// Test OnAuthenticate hook
	authenticated, err := mockHooks.OnAuthenticate("test", "password", OAuthState{})
	assert.NoError(t, err)
	assert.True(t, authenticated)
	assert.True(t, mockHooks.PostAuthCalled)

	// Test OnUserGet hook
	user, err := mockHooks.OnUserGet("123")
	assert.NoError(t, err)
	assert.Equal(t, mockHooks.TestUser, user)
	assert.True(t, mockHooks.PreLoginCalled)

	// Test OnSessionValidate hook
	validatedUser, err := mockHooks.OnSessionValidate(cookieContents)
	assert.NoError(t, err)
	assert.Equal(t, mockHooks.TestUser, validatedUser)
	assert.True(t, mockHooks.PostLoginCalled)

	// Test OnSessionDestroy hook
	err = mockHooks.OnSessionDestroy("test-session")
	assert.NoError(t, err)
	assert.True(t, mockHooks.LogoutCalled)
}

// Test default hook behavior
func TestHooks_DefaultBehavior(t *testing.T) {
	// Create a new server with default options and a secret key
	server := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	// Create a test HTTP request and context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest("GET", "/test", nil)
	c.Request = req

	// Create a test user
	testUser := Claims{
		Email:  "test@example.com",
		UserID: "123",
		Role:   "user",
	}

	// Test that default hooks don't panic
	defaultHooks := &DefaultAuthHooks{s: server}

	// Test OnUserCreate
	userID, err := defaultHooks.OnUserCreate(testUser)
	assert.NoError(t, err)
	assert.Equal(t, testUser.UserID, userID)

	// Test GetUserOrCreate
	cookieContents, err := defaultHooks.GetUserOrCreate(testUser)
	assert.NoError(t, err)
	assert.NotNil(t, cookieContents)

	// Test OnAuthenticate
	authenticated, err := defaultHooks.OnAuthenticate("test", "password", OAuthState{})
	assert.Error(t, err) // Default implementation returns an error
	assert.False(t, authenticated)

	// Test OnUserGet
	_, err = defaultHooks.OnUserGet("123")
	assert.Error(t, err) // Default implementation returns an error

	// Test OnSessionValidate
	_, err = defaultHooks.OnSessionValidate(cookieContents)
	assert.Error(t, err) // Default implementation returns an error

	// Test OnSessionCreate
	_, err = defaultHooks.OnSessionCreate("123")
	assert.Error(t, err) // Default implementation returns an error

	// Test OnSessionDestroy
	err = defaultHooks.OnSessionDestroy("test-session")
	assert.Error(t, err) // Default implementation returns an error

	// Test OnOAuthCallbackSuccess
	err = defaultHooks.OnOAuthCallbackSuccess(c, OAuthState{})
	assert.NoError(t, err) // Default implementation returns nil
}
