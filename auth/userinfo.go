package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

var userInfoEndpoints = map[string]string{
	"google": "https://www.googleapis.com/oauth2/v3/userinfo",
}

// GetUserInfo fetches the remote user info from the provider-specific endpoint.
func (a *AuthModule) GetUserInfo(ctx context.Context, token *oauth2.Token) (*StatelessUser, error) {
	provider := strings.ToLower(strings.TrimSpace(a.defaultProvider))
	endpoint, ok := userInfoEndpoints[provider]
	if !ok {
		return nil, fmt.Errorf("no userinfo endpoint configured for provider %q", provider)
	}

	client := a.config.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build userinfo request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("userinfo %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Subject string `json:"sub"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return &StatelessUser{Name: payload.Name, Email: payload.Email, Picture: payload.Picture}, nil
}
