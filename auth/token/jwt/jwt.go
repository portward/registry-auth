package jwt

import (
	"fmt"

	"github.com/docker/libtrust"
	"github.com/golang-jwt/jwt/v4"
)

func detectSigningMethod(signingKey libtrust.PrivateKey) (jwt.SigningMethod, error) {
	switch signingKey.KeyType() {
	case "RSA":
		return jwt.SigningMethodRS256, nil
	case "EC":
		return jwt.SigningMethodES256, nil
	}

	return nil, fmt.Errorf("unsupported signing key type %q", signingKey.KeyType())
}
