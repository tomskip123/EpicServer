package auth

import (
	"net/http"
	"time"
)

func (a *AuthModule) readSessionID(r *http.Request) (string, bool) {
	c, err := r.Cookie(a.cookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func (a *AuthModule) writeSessionCookie(w http.ResponseWriter, session *Session) {
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge <= 0 {
		maxAge = int(a.sessionTTL.Seconds())
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    session.ID,
		Path:     a.cookiePath,
		Domain:   a.cookieDomain,
		Secure:   a.cookieSecure,
		HttpOnly: a.cookieHTTPOnly,
		SameSite: a.cookieSameSite,
		Expires:  session.ExpiresAt,
		MaxAge:   maxAge,
	})
}

func (a *AuthModule) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     a.cookiePath,
		Domain:   a.cookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   a.cookieSecure,
		HttpOnly: a.cookieHTTPOnly,
		SameSite: a.cookieSameSite,
	})
}
