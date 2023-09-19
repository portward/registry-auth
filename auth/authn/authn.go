package authn

import (
	"context"
	"maps"

	"golang.org/x/crypto/bcrypt"

	"github.com/portward/registry-auth/auth"
)

// UserAuthenticator is a static list of users.
type UserAuthenticator struct {
	entries map[string]User
}

// NewUserAuthenticator returns a new UserAuthenticator.
func NewUserAuthenticator(users []User) UserAuthenticator {
	entries := make(map[string]User, len(users))

	for _, user := range users {
		entries[user.Username] = user
	}

	return UserAuthenticator{
		entries: entries,
	}
}

// User is an auth.Subject.
type User struct {
	Enabled      bool
	Username     string
	PasswordHash string
	Attrs        map[string]string
}

// ID implements auth.Subject.
func (u User) ID() auth.SubjectID {
	return auth.SubjectIDFromString(u.Username)
}

// Attribute implements auth.Subject.
func (u User) Attribute(key string) (string, bool) {
	if u.Attrs == nil {
		return "", false
	}

	v, ok := u.Attrs[key]

	return v, ok
}

// Attributes implements auth.Subject.
func (u User) Attributes() map[string]string {
	return maps.Clone(u.Attrs)
}

// AuthenticatePassword implements auth.PasswordAuthenticator.
func (a UserAuthenticator) AuthenticatePassword(_ context.Context, username string, password string) (auth.Subject, error) {
	if a.entries == nil {
		return nil, auth.ErrAuthenticationFailed
	}

	user, ok := a.entries[username]
	if !ok || !user.Enabled {
		// timing attack paranoia
		_ = bcrypt.CompareHashAndPassword([]byte{}, []byte(password))

		return nil, auth.ErrAuthenticationFailed
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, auth.ErrAuthenticationFailed
	}

	return user, nil
}

// GetSubjectByID implements SubjectRepository.
func (a UserAuthenticator) GetSubjectByID(_ context.Context, id auth.SubjectID) (auth.Subject, error) {
	user, ok := a.entries[id.String()]
	if !ok || !user.Enabled {
		return nil, auth.ErrAuthenticationFailed
	}

	return user, nil
}

// RefreshTokenAuthenticator authenticates a refresh token and returns the auth.Subject it belongs to.
type RefreshTokenAuthenticator struct {
	verifier          RefreshTokenVerifier
	subjectRepository SubjectRepository
}

// NewRefreshTokenAuthenticator returns a new RefreshTokenAuthenticator.
func NewRefreshTokenAuthenticator(verifier RefreshTokenVerifier, subjectRepository SubjectRepository) RefreshTokenAuthenticator {
	return RefreshTokenAuthenticator{
		verifier:          verifier,
		subjectRepository: subjectRepository,
	}
}

// RefreshTokenVerifier verifies a refresh token and returns the Subject ID it belongs to.
type RefreshTokenVerifier interface {
	VerifyRefreshToken(ctx context.Context, service string, refreshToken string) (auth.SubjectID, error)
}

// SubjectRepository looks up an auth.Subject based on an identifier.
type SubjectRepository interface {
	GetSubjectByID(ctx context.Context, id auth.SubjectID) (auth.Subject, error)
}

// AuthenticateRefreshToken implements auth.RefreshTokenAuthenticator.
func (a RefreshTokenAuthenticator) AuthenticateRefreshToken(ctx context.Context, service string, refreshToken string) (auth.Subject, error) {
	subjectID, err := a.verifier.VerifyRefreshToken(ctx, service, refreshToken)
	if err != nil {
		return nil, err
	}

	subject, err := a.subjectRepository.GetSubjectByID(ctx, subjectID)
	if err != nil {
		return nil, err
	}

	return subject, nil
}
