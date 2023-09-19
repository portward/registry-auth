package auth

import (
	"context"
	"time"
)

// AccessToken is a credential issued to a registry client described in the [AccessToken Authentication Specification].
//
// [AccessToken Authentication Specification]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type AccessToken struct {
	Payload string

	ExpiresIn time.Duration
	IssuedAt  time.Time
}

// AccessTokenIssuer issues a token described in the [Token Authentication Specification].
//
// [Token Authentication Specification]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type AccessTokenIssuer interface {
	IssueAccessToken(ctx context.Context, service string, subject Subject, grantedScopes []Scope) (AccessToken, error)
}

// RefreshTokenIssuer issues a token that a client can use to issue a new token for a subject without presenting credentials again.
// TODO: add service as a parameter.
type RefreshTokenIssuer interface {
	IssueRefreshToken(ctx context.Context, service string, subject Subject) (string, error)
}
