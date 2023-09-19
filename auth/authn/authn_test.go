package authn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/portward/registry-auth/auth"
)

func TestUserAuthenticator(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		const (
			username = "user"
			password = "password"
		)

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
		require.NoError(t, err)

		user := User{
			Enabled:      true,
			Username:     username,
			PasswordHash: string(passwordHash),
		}

		authenticator := NewUserAuthenticator([]User{user})

		subject, err := authenticator.AuthenticatePassword(context.Background(), username, password)
		require.NoError(t, err)

		assert.Equal(t, user, subject)
	})

	t.Run("Error", func(t *testing.T) {
		t.Run("DisabledUser", func(t *testing.T) {
			user := User{
				Enabled: false,
			}

			authenticator := NewUserAuthenticator([]User{user})

			_, err := authenticator.AuthenticatePassword(context.Background(), "username", "password")
			require.Error(t, err)

			assert.ErrorIs(t, err, auth.ErrAuthenticationFailed)
		})

		t.Run("PasswordMismatch", func(t *testing.T) {
			const (
				username = "user"
			)

			passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), 10)
			require.NoError(t, err)

			user := User{
				Enabled:      true,
				Username:     username,
				PasswordHash: string(passwordHash),
			}

			authenticator := NewUserAuthenticator([]User{user})

			_, err = authenticator.AuthenticatePassword(context.Background(), username, "otherPassword")
			require.Error(t, err)

			assert.ErrorIs(t, err, auth.ErrAuthenticationFailed)
		})
	})
}

func TestUser(t *testing.T) {
	const (
		username  = "username"
		attrKey   = "key"
		attrValue = "value"
	)

	user := User{
		Username: username,
		Attrs: map[string]string{
			attrKey: attrValue,
		},
	}

	assert.Equal(t, auth.SubjectIDFromString(username), user.ID())

	val, ok := user.Attribute(attrKey)
	assert.Equal(t, attrValue, val)
	assert.True(t, ok)

	assert.Equal(t, user.Attrs, user.Attributes())
}

type refreshTokenVerifier struct {
	refreshTokens map[string]auth.SubjectID
}

func (v refreshTokenVerifier) VerifyRefreshToken(_ context.Context, _ string, refreshToken string) (auth.SubjectID, error) {
	return v.refreshTokens[refreshToken], nil
}

func TestRefreshTokenAuthenticator(t *testing.T) {
	const refreshToken = "refresh token"

	user := User{
		Enabled:      true,
		Username:     "user",
		PasswordHash: "",
	}

	verifier := refreshTokenVerifier{
		refreshTokens: map[string]auth.SubjectID{
			refreshToken: user.ID(),
		},
	}
	subjectRepository := NewUserAuthenticator([]User{user})

	authenticator := NewRefreshTokenAuthenticator(verifier, subjectRepository)

	subject, err := authenticator.AuthenticateRefreshToken(context.Background(), "service", refreshToken)
	require.NoError(t, err)

	assert.Equal(t, user, subject)
}
