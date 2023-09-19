package jwt

// AccessTokenIssuerOption configures a AccessTokenIssuer.
type AccessTokenIssuerOption interface {
	applyAccessTokenIssuer(i *AccessTokenIssuer)
}

// RefreshTokenIssuerOption configures a RefreshTokenIssuer.
type RefreshTokenIssuerOption interface {
	applyRefreshTokenIssuer(i *RefreshTokenIssuer)
}

// Option configures a token issuer.
type Option interface {
	AccessTokenIssuerOption
	RefreshTokenIssuerOption
}

// WithClock configures a token issuer to use a Clock.
func WithClock(clock Clock) Option {
	return withClock{clock}
}

type withClock struct {
	clock Clock
}

func (w withClock) applyAccessTokenIssuer(i *AccessTokenIssuer) {
	i.clock = w.clock
}

func (w withClock) applyRefreshTokenIssuer(i *RefreshTokenIssuer) {
	i.clock = w.clock
}

// WIthIDGenerator configures a token issuer to use an IDGenerator.
func WithIDGenerator(idGenerator IDGenerator) AccessTokenIssuerOption {
	return withIDGenerator{idGenerator}
}

type withIDGenerator struct {
	idGenerator IDGenerator
}

func (w withIDGenerator) applyAccessTokenIssuer(i *AccessTokenIssuer) {
	i.idGenerator = w.idGenerator
}
