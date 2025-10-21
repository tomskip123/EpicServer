package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

func (a *AuthModule) handleLogin(w http.ResponseWriter, r *http.Request) {
	// if there is a next parameter in the url query, add that to state for callback to handle.
	next := r.URL.Query().Get("next")

	// then we set up a state store.
	state, err := a.states.New(a.stateTTL, a.now, next)
	if err != nil {
		http.Error(w, "failed to initiate oauth flow", http.StatusInternalServerError)
		return
	}

	redirectURL := a.config.RedirectURL
	if redirectURL == "" {
		redirectURL = a.resolveRedirectURL(r)
	}

	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if redirectURL != "" {
		options = append(options, oauth2.SetAuthURLParam("redirect_uri", redirectURL))
	}

	authURL := a.config.AuthCodeURL(state, options...)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *AuthModule) handleCallback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		a.fail(w, r, errors.New(errParam))
		return
	}

	state := r.URL.Query().Get("state")
	stateItem := a.states.Consume(state, a.now())
	if state == "" || stateItem == nil {
		a.fail(w, r, errors.New("invalid oauth state"))
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		a.fail(w, r, errors.New("missing oauth code"))
		return
	}

	redirectURL := a.config.RedirectURL
	if redirectURL == "" {
		redirectURL = a.resolveRedirectURL(r)
	}

	var exchangeOpts []oauth2.AuthCodeOption
	if redirectURL != "" {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("redirect_uri", redirectURL))
	}

	token, err := a.config.Exchange(r.Context(), code, exchangeOpts...)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	session, err := a.sessions.Create(token, a.sessionTTL, a.now())
	if err != nil {
		a.fail(w, r, err)
		return
	}

	userInfo, err := a.GetUserInfo(r.Context(), token)
	if err != nil {
		if a.loggers.Error != nil {
			a.loggers.Error.Fatal(err)
		}
	}

	if a.user != nil && a.user.IsEnabled() {
		if _, err = a.user.RegisterUser(r.Context(), userInfo); err != nil {
			if a.loggers.Info != nil {
				a.loggers.Info.Println(err)
			}
		}
	}

	// if redirect exists on the state item we redirect there instead.
	redirectPath := a.loginRedirectURL
	if stateItem.Redirect != "" {
		redirectPath = stateItem.Redirect
	}

	a.writeSessionCookie(w, session)
	a.redirect(w, r, redirectPath)
}

func (a *AuthModule) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := a.readSessionID(r)
	if ok {
		a.sessions.Delete(sessionID)
	}
	a.clearSessionCookie(w)
	a.redirect(w, r, a.logoutRedirectURL)
}

func (a *AuthModule) redirect(w http.ResponseWriter, r *http.Request, url string) {
	if url == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *AuthModule) fail(w http.ResponseWriter, r *http.Request, err error) {
	if a.failureRedirectURL != "" {
		http.Redirect(w, r, a.failureRedirectURL, http.StatusFound)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func (a *AuthModule) resolveRedirectURL(r *http.Request) string {
	scheme := requestScheme(r)
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, a.callbackPath)
}

func requestScheme(r *http.Request) string {
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto != "" {
		if idx := strings.IndexByte(proto, ','); idx >= 0 {
			proto = proto[:idx]
		}
		proto = strings.TrimSpace(proto)
		if proto != "" {
			return strings.ToLower(proto)
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
