package jwt

import (
	"context"
	"encoding/json"
	"time"

	"github.com/docker/libtrust"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jonboulle/clockwork"

	"github.com/portward/registry-auth/auth"
)

type accessTokenClaims struct {
	jwt.RegisteredClaims

	Access []auth.Scope `json:"access"`
}

// AccessTokenIssuer issues access tokens according to the [Token Authentication Specification] and [Token Authentication Implementation].
//
// [Token Authentication Specification]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
// [Token Authentication Implementation]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/jwt.md
type AccessTokenIssuer struct {
	issuer     string
	signingKey libtrust.PrivateKey
	expiration time.Duration

	idGenerator IDGenerator
	clock       Clock
}

// NewAccessTokenIssuer returns a new AccessTokenIssuer.
func NewAccessTokenIssuer(issuer string, signingKey libtrust.PrivateKey, expiration time.Duration, opts ...AccessTokenIssuerOption) AccessTokenIssuer {
	if expiration <= 0 {
		panic("expiration cannot be zero")
	}

	i := AccessTokenIssuer{
		issuer:     issuer,
		signingKey: signingKey,
		expiration: expiration,
	}

	for _, opt := range opts {
		opt.applyAccessTokenIssuer(&i)
	}

	if i.idGenerator == nil {
		i.idGenerator = uuidGenerator{}
	}

	if i.clock == nil {
		i.clock = clockwork.NewRealClock()
	}

	return i
}

func (i AccessTokenIssuer) IssueAccessToken(_ context.Context, service string, subject auth.Subject, grantedScopes []auth.Scope) (auth.AccessToken, error) {
	alg, err := detectSigningMethod(i.signingKey)
	if err != nil {
		return auth.AccessToken{}, err
	}

	id, err := i.idGenerator.GenerateID()
	if err != nil {
		return auth.AccessToken{}, err
	}

	now := i.clock.Now()

	claims := accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			Issuer:    i.issuer,
			Subject:   subject.ID().String(),
			Audience:  []string{service},
			ExpiresAt: jwt.NewNumericDate(now.Add(i.expiration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Access: grantedScopes,
	}

	token := jwt.NewWithClaims(alg, claims)

	if x5c := i.signingKey.GetExtendedField("x5c"); x5c != nil {
		token.Header["x5c"] = x5c.([]string)
	} else {
		var jwkMessage json.RawMessage
		jwkMessage, err = i.signingKey.PublicKey().MarshalJSON()
		if err != nil {
			return auth.AccessToken{}, err
		}
		token.Header["jwk"] = &jwkMessage
	}

	signedToken, err := token.SignedString(i.signingKey.CryptoPrivateKey())
	if err != nil {
		return auth.AccessToken{}, err
	}

	return auth.AccessToken{
		Payload:   signedToken,
		ExpiresIn: i.expiration,
		IssuedAt:  now,
	}, nil
}
