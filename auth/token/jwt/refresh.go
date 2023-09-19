package jwt

import (
	"context"

	"github.com/docker/libtrust"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jonboulle/clockwork"

	"github.com/portward/registry-auth/auth"
)

// RefreshTokenIssuer issues a refresh token.
type RefreshTokenIssuer struct {
	issuer     string
	signingKey libtrust.PrivateKey

	clock Clock
}

// NewRefreshTokenIssuer returns a new RefreshTokenIssuer.
func NewRefreshTokenIssuer(issuer string, signingKey libtrust.PrivateKey, opts ...RefreshTokenIssuerOption) RefreshTokenIssuer {
	i := RefreshTokenIssuer{
		issuer:     issuer,
		signingKey: signingKey,
	}

	for _, opt := range opts {
		opt.applyRefreshTokenIssuer(&i)
	}

	if i.clock == nil {
		i.clock = clockwork.NewRealClock()
	}

	return i
}

// IssueRefreshToken implements auth.RefreshTokenIssuer.
func (i RefreshTokenIssuer) IssueRefreshToken(_ context.Context, service string, subject auth.Subject) (string, error) {
	alg, err := detectSigningMethod(i.signingKey)
	if err != nil {
		return "", err
	}

	now := i.clock.Now()

	claims := jwt.RegisteredClaims{
		Issuer:    i.issuer,
		Subject:   subject.ID().String(),
		Audience:  []string{service},
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(alg, claims)

	signedToken, err := token.SignedString(i.signingKey.CryptoPrivateKey())
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// VerifyRefreshToken implements authn.RefreshTokenVerifier.
func (i RefreshTokenIssuer) VerifyRefreshToken(_ context.Context, service string, refreshToken string) (auth.SubjectID, error) {
	var claims jwt.RegisteredClaims

	token, err := jwt.ParseWithClaims(refreshToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return i.signingKey.CryptoPublicKey(), nil
	})
	if err != nil {
		return nil, err
	}
	// TODO: validate audience/service/issuer?

	if !token.Valid { //nolint:staticcheck,revive
		// TODO: return error?
	}

	claims.VerifyAudience(service, true)
	claims.VerifyIssuer(i.issuer, true)

	return auth.SubjectIDFromString(claims.Subject), nil
}
