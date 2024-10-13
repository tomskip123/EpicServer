package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
)

func GenerateCSRFToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(token), nil
}

// IsTrustedSource IsTrustedSource checks if the request is from a trusted source
func IsTrustedSource(r *http.Request) bool {
	// Example: Bypass CSRF check for internal IP addresses
	internalIPs := []string{"127.0.0.1", "::1"}
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fmt.Println(err)
		return false
	}

	for _, ip := range internalIPs {
		if clientIP == ip {
			return true
		}
	}

	// Example: Bypass CSRF check for specific user agents
	trustedUserAgents := []string{"InternalServiceClient"}
	userAgent := r.UserAgent()

	for _, ua := range trustedUserAgents {
		if userAgent == ua {
			return true
		}
	}

	// Example: Bypass CSRF check for requests with a specific header
	if r.Header.Get("X-Internal-Request") == "true" {
		return true
	}

	return false
}
