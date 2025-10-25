package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"path"
	"strings"
)

func randomString(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func sanitizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func GetUserFromReq(auth *AuthModule, r *http.Request) (*StatelessUser, error) {
	session, authenticated := SessionFromContext(r.Context())
	if !authenticated {
		return nil, errors.New("not authenticated")
	}

	userinfo := userInfoCache.Get(session.Email)
	if userinfo != nil {
		return userinfo, nil
	}

	userinfo, err := auth.GetUserInfo(r.Context(), session.Token)
	if err != nil {
		return nil, errors.New("can't get stateless user from request")
	}

	// if not found add user to cache
	userInfoCache.Add(userinfo)

	return userinfo, nil
}
