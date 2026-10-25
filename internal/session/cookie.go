package session

import (
	"crypto/rand"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

const (
	loginCookie   = "__Host-fintrace-login"
	sessionCookie = "__Host-fintrace-session"
)

type loginCookieValue struct {
	state, nonce, verifier string
}

func newLoginCookieValue() loginCookieValue {
	return loginCookieValue{
		state:    rand.Text(),
		nonce:    rand.Text(),
		verifier: oauth2.GenerateVerifier(),
	}
}

func (f loginCookieValue) cookieValue() string {
	return f.state + "." + f.nonce + "." + f.verifier
}

func parseLoginCookie(cookie *http.Cookie) (loginCookieValue, error) {
	parts := strings.Split(cookie.Value, ".")

	if len(parts) != 3 ||
		parts[0] == "" ||
		parts[1] == "" ||
		parts[2] == "" {
		return loginCookieValue{}, errors.New("cookie value has wrong format")
	}

	return loginCookieValue{state: parts[0], nonce: parts[1], verifier: parts[2]}, nil
}

func configureSecureCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Secure:   true,
		Path:     "/",
		Domain:   "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Value:    value,
	}
}
