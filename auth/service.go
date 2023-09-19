package auth

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"
)

// TokenService implements both the [Docker Registry v2 authentication] and the [Docker Registry v2 OAuth2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
type TokenService interface {
	// TokenHandler implements the [Docker Registry v2 authentication] specification.
	//
	// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
	TokenHandler(ctx context.Context, r TokenRequest) (TokenResponse, error)

	// OAuth2Handler implements the [Docker Registry v2 OAuth2 authentication] specification.
	//
	// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
	OAuth2Handler(ctx context.Context, r OAuth2Request) (OAuth2Response, error)
}

// TokenRequest implements the token request defined in the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type TokenRequest struct {
	Service  string
	ClientID string
	Offline  bool
	Scopes   Scopes

	Anonymous bool
	Username  string
	Password  string
}

func (r TokenRequest) Validate() error {
	if r.Service == "" {
		return errors.New("service is required")
	}

	if r.ClientID == "" { //nolint
		// return errors.New("client ID is required")
	}

	return nil
}

// TokenResponse implements the token response defined in the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type TokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// OAuth2Request implements the token request defined in the [Docker Registry v2 OAuth2 authentication] specification.
//
// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
type OAuth2Request struct {
	GrantType string

	Service    string
	ClientID   string
	AccessType string
	Scopes     Scopes

	Username     string
	Password     string
	RefreshToken string
}

// TODO: oauth2 error
func (r OAuth2Request) Validate() error {
	if r.Service == "" {
		return errors.New("service is required")
	}

	if r.ClientID == "" {
		return errors.New("client ID is required")
	}

	if r.GrantType == "" {
		return errors.New("missing grant_type value")
	}

	if !slices.Contains(validGrantTypes, r.GrantType) {
		return errors.New("unknown grant_type value")
	}

	if r.GrantType == GrantTypeRefreshToken {
		if r.RefreshToken == "" {
			return errors.New("missing refresh_token value")
		}
	}

	if r.GrantType == GrantTypePassword {
		if r.Username == "" {
			return errors.New("missing username value")
		}

		if r.Password == "" {
			return errors.New("missing password value")
		}
	}

	if !slices.Contains(validAccessTypes, r.AccessType) {
		return errors.New("unknown access_type value")
	}

	return nil
}

const (
	GrantTypeRefreshToken = "refresh_token"
	GrantTypePassword     = "password"

	AccessTypeOnline  = "online"
	AccessTypeOffline = "offline"
)

var validGrantTypes = []string{
	GrantTypeRefreshToken,
	GrantTypePassword,
}

var validAccessTypes = []string{
	"",
	AccessTypeOnline,
	AccessTypeOffline,
}

// OAuth2Response implements the token response defined in the [Docker Registry v2 OAuth2 authentication] specification.
//
// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
type OAuth2Response struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Authenticator is a facade combining different type of authenticators.
type Authenticator struct {
	PasswordAuthenticator
	RefreshTokenAuthenticator
}

// TokenIssuer is a facade combining different type of token issuers.
type TokenIssuer struct {
	AccessTokenIssuer
	RefreshTokenIssuer
}

// TokenServer implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/index.md
type TokenServiceImpl struct {
	Authenticator Authenticator
	Authorizer    Authorizer
	TokenIssuer   TokenIssuer
}

// TokenHandler implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
func (s TokenServiceImpl) TokenHandler(ctx context.Context, r TokenRequest) (TokenResponse, error) {
	if err := r.Validate(); err != nil {
		return TokenResponse{}, err
	}

	var subject Subject

	if !r.Anonymous {
		var err error

		subject, err = s.Authenticator.AuthenticatePassword(ctx, r.Username, r.Password)
		if err != nil {
			return TokenResponse{}, err
		}
	}

	grantedScopes, err := s.Authorizer.Authorize(ctx, subject, r.Scopes)
	if err != nil {
		return TokenResponse{}, err
	}

	token, err := s.TokenIssuer.IssueAccessToken(ctx, r.Service, subject, grantedScopes)
	if err != nil {
		return TokenResponse{}, err
	}

	response := TokenResponse{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
	}

	if r.Offline && subject != nil {
		refreshToken, err := s.TokenIssuer.IssueRefreshToken(ctx, r.Service, subject)
		if err != nil {
			return TokenResponse{}, err
		}

		response.RefreshToken = refreshToken
	}

	return response, nil
}

func (s TokenServiceImpl) OAuth2Handler(ctx context.Context, r OAuth2Request) (OAuth2Response, error) {
	if err := r.Validate(); err != nil {
		return OAuth2Response{}, err
	}

	var subject Subject
	var refreshToken string

	switch r.GrantType {
	case GrantTypeRefreshToken:
		var err error

		subject, err = s.Authenticator.AuthenticateRefreshToken(ctx, r.Service, r.RefreshToken)
		if err != nil {
			return OAuth2Response{}, err
		}

		refreshToken = r.RefreshToken
	case GrantTypePassword:
		var err error

		subject, err = s.Authenticator.AuthenticatePassword(ctx, r.Username, r.Password)
		if err != nil {
			return OAuth2Response{}, err
		}
	default:
		// This should never happen
		return OAuth2Response{}, errors.New("unknown grant_type value")
	}

	grantedScopes, err := s.Authorizer.Authorize(ctx, subject, r.Scopes)
	if err != nil {
		return OAuth2Response{}, err
	}

	token, err := s.TokenIssuer.IssueAccessToken(ctx, r.Service, subject, grantedScopes)
	if err != nil {
		return OAuth2Response{}, err
	}

	response := OAuth2Response{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
		IssuedAt:  token.IssuedAt.Format(time.RFC3339),
		Scope:     Scopes(grantedScopes).String(),
	}

	if r.AccessType == AccessTypeOffline && subject != nil && r.GrantType == GrantTypeRefreshToken {
		token, err := s.TokenIssuer.IssueRefreshToken(ctx, r.Service, subject)
		if err != nil {
			return OAuth2Response{}, err
		}

		refreshToken = token
	}

	if refreshToken != "" {
		response.RefreshToken = refreshToken
	}

	return response, nil
}

// LoggerTokenService acts as a middleware for a TokenService and logs every request.
type LoggerTokenService struct {
	Service TokenService
	Logger  *slog.Logger
}

// TokenHandler implements TokenService and logs every request.
func (s LoggerTokenService) TokenHandler(ctx context.Context, r TokenRequest) (TokenResponse, error) {
	resp, err := s.Service.TokenHandler(ctx, r)

	logger := s.Logger.With(
		// TODO: correlation ID
		slog.String("client_id", r.ClientID),
		slog.String("service", r.Service),
		slog.String("scopes", r.Scopes.String()),
		slog.Bool("offline", r.Offline),
		slog.Bool("anonymous", r.Anonymous),
	)

	if err != nil && !(errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrAuthenticationFailed)) {
		logger.Error("authorization failed", slog.Any("error", err))
	} else if err != nil {
		logger.Info("authorization failed due to client error", slog.Any("error", err))
	} else {
		logger.Info("client authorized")
	}

	return resp, err
}

// OAuth2Handler implements TokenService and logs every request.
func (s LoggerTokenService) OAuth2Handler(ctx context.Context, r OAuth2Request) (OAuth2Response, error) {
	resp, err := s.Service.OAuth2Handler(ctx, r)

	logger := s.Logger.With(
		// TODO: correlation ID
		slog.String("client_id", r.ClientID),
		slog.String("service", r.Service),
		slog.String("scopes", r.Scopes.String()),
		slog.Bool("offline", r.AccessType == AccessTypeOffline),
		slog.String("grant_type", r.GrantType),
	)

	if err != nil && !(errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrAuthenticationFailed)) {
		logger.Error("authorization failed", slog.Any("error", err))
	} else if err != nil {
		logger.Info("authorization failed due to client error", slog.Any("error", err))
	} else {
		logger.Info("client authorized")
	}

	return resp, err
}
