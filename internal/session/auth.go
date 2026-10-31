package session

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

type Auth struct {
	oidc           *OIDC
	client         *http.Client
	store          Store
	sessionIdle    time.Duration
	sessionMaxAge  time.Duration
	now            func() time.Time
	sessionLoads   singleflight.Group
	userIDResolver UserIDResolver
}

func NewAuth(ctx context.Context, cfg config.Config, client *http.Client, userIDResolver UserIDResolver, store Store) (*Auth, error) {
	o, err := newOIDC(ctx, cfg, client)
	if err != nil {
		return nil, err
	}
	return &Auth{
		oidc:           o,
		client:         client,
		store:          store,
		sessionIdle:    cfg.SessionIdle,
		sessionMaxAge:  cfg.SessionMax,
		now:            time.Now,
		userIDResolver: userIDResolver,
	}, nil
}
