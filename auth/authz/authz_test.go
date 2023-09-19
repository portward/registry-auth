package authz

import (
	"context"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/portward/registry-auth/auth"
)

type subject struct {
	id         auth.SubjectID
	attributes map[string]string
}

func (s subject) ID() auth.SubjectID {
	return s.id
}

func (s subject) Attribute(key string) (string, bool) {
	if s.attributes == nil {
		return "", false
	}

	v, ok := s.attributes[key]

	return v, ok
}

func (s subject) Attributes() map[string]string {
	return maps.Clone(s.attributes)
}

type repositoryAuthorizerStub struct {
	repositories map[string]bool
}

func (a repositoryAuthorizerStub) Authorize(_ context.Context, name string, _ auth.Subject, actions []string) ([]string, error) {
	if !a.repositories[name] {
		return []string{}, nil
	}

	return actions, nil
}

func TestDefaultAuthorizer(t *testing.T) {
	subject := subject{
		id: auth.SubjectIDFromString("user"),
	}

	testCases := []struct {
		subject        auth.Subject
		scopes         []auth.Scope
		expectedScopes []auth.Scope
	}{
		{
			subject: subject,
			scopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "registry",
						Name: "catalog",
					},
					Actions: []string{"search"},
				},
			},
			expectedScopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "registry",
						Name: "catalog",
					},
					Actions: []string{"search"},
				},
			},
		},
		{
			subject: subject,
			scopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "user/repository",
					},
					Actions: []string{"push", "pull"},
				},
			},
			expectedScopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "user/repository",
					},
					Actions: []string{"push", "pull"},
				},
			},
		},
	}

	authorizer := NewDefaultAuthorizer(
		repositoryAuthorizerStub{
			repositories: map[string]bool{
				"user/repository": true,
			},
		},
		false,
	)

	for _, testCase := range testCases {
		testCase := testCase

		t.Run("", func(t *testing.T) {
			grantedScopes, err := authorizer.Authorize(context.Background(), testCase.subject, testCase.scopes)
			require.NoError(t, err)

			assert.Equal(t, testCase.expectedScopes, grantedScopes)
		})
	}
}
