package session

import "context"

const testUserID = "0192f3a0-0000-7000-8000-000000000001"

// A UserIDResolver standing in for Core: it answers testUserID, or err when set.
type fakeUserIDResolver struct {
	err error
}

var _ UserIDResolver = (*fakeUserIDResolver)(nil)

func (f *fakeUserIDResolver) UserID(context.Context, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return testUserID, nil
}
