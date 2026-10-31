package coreapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type UsersAPI struct {
	baseURL *url.URL
	client  *http.Client
}

const currentUserIDPath = "api/v1/users/current/id"

func NewUsersAPI(baseURL *url.URL, client *http.Client) *UsersAPI {
	return &UsersAPI{baseURL: baseURL, client: client}
}

// UserID implements [session.UserIDResolver].
func (u *UsersAPI) UserID(ctx context.Context, accessToken string) (string, error) {
	endpoint := u.baseURL.JoinPath(currentUserIDPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build user id request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("call core: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("core answered %s", resp.Status)
	}

	var body struct {
		UserID string `json:"userId"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body); err != nil {
		return "", fmt.Errorf("decode user id: %w", err)
	}

	if body.UserID == "" {
		return "", fmt.Errorf("core answered no user id")
	}

	return body.UserID, nil
}
