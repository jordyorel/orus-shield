package account

import (
	"context"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Profile returns what Profil shows about the signed-in user.
func (s *Service) Profile(ctx context.Context, sess store.Session) (store.Profile, error) {
	return s.auth.Profile(ctx, sess.UserID)
}

// SetName changes the user's display name; store.ErrInvalidName when it
// does not fit.
func (s *Service) SetName(ctx context.Context, sess store.Session, name string, c Client) error {
	n, err := store.NormalizeName(name)
	if err != nil {
		return err
	}
	return s.auth.SetName(ctx, sess.UserID, sess.Email, n, c.IP)
}

// Sessions lists the user's open sessions; token is the caller's own.
func (s *Service) Sessions(ctx context.Context, sess store.Session, token string) ([]store.DeviceSession, error) {
	return s.auth.Sessions(ctx, sess.UserID, token, s.cfg.SessionIdle)
}

// EndSession closes one of the user's own sessions.
func (s *Service) EndSession(ctx context.Context, sess store.Session, id string, c Client) error {
	return s.auth.EndSession(ctx, sess.UserID, sess.Email, id, c.IP)
}

// Activity returns the user's latest security events.
func (s *Service) Activity(ctx context.Context, sess store.Session, limit int) ([]store.AuthActivity, error) {
	return s.auth.Activity(ctx, sess.UserID, limit)
}
