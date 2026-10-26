package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/oauth2"
)

// Returns ErrNoSession when the realm has ended the session; any other error leaves it usable.
func (a *Auth) refreshSession(ctx context.Context, s Session, now time.Time) (Session, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)
	token, err := a.oidc.OAuth2.TokenSource(ctx, &oauth2.Token{RefreshToken: s.RefreshToken}).Token()

	var re *oauth2.RetrieveError
	if errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
		slog.InfoContext(ctx, "Session ended by the realm", "sub", s.Subject)
		return Session{}, ErrNoSession
	}
	if err != nil {
		slog.WarnContext(ctx, "Session not refreshed", "sub", s.Subject, "error", err)
		return Session{}, fmt.Errorf("refresh session: %w", err)
	}

	if raw, ok := token.Extra("id_token").(string); ok && raw != "" {
		idToken, err := a.oidc.Verifier.Verify(ctx, raw)
		if err != nil {
			slog.WarnContext(ctx, "Refreshed ID token not verified", "sub", s.Subject, "error", err)
			return Session{}, fmt.Errorf("verify refreshed ID token: %w", err)
		}
		if idToken.Subject != s.Subject {
			slog.ErrorContext(ctx, "Refreshed ID token names another subject", "sub", s.Subject, "got", idToken.Subject)
			return Session{}, ErrNoSession
		}
		s.IDToken = raw
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.AccessExpiry = token.Expiry
	s.RefreshExpiry = refreshExpiry(token, now)
	slog.DebugContext(ctx, "Session refreshed", "sub", s.Subject)
	return s, nil
}
