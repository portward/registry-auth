package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/portward/registry-auth/auth"
)

func TestParseScope(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		testCases := []struct {
			scope    string
			expected auth.Scope
		}{
			{
				"repository:path/to/repo:pull,push",
				auth.Scope{
					Resource: auth.Resource{
						Type:  "repository",
						Class: "",
						Name:  "path/to/repo",
					},
					Actions: []string{"pull", "push"},
				},
			},
			{
				"repository:path/to/repo: pull , push ",
				auth.Scope{
					Resource: auth.Resource{
						Type:  "repository",
						Class: "",
						Name:  "path/to/repo",
					},
					Actions: []string{"pull", "push"},
				},
			},
			{
				"repository(class):path/to/repo:pull",
				auth.Scope{
					Resource: auth.Resource{
						Type:  "repository",
						Class: "class",
						Name:  "path/to/repo",
					},
					Actions: []string{"pull"},
				},
			},
			{
				"repository:path/to/repo:pull,push,pull", // duplicates are allowed for now
				auth.Scope{
					Resource: auth.Resource{
						Type:  "repository",
						Class: "",
						Name:  "path/to/repo",
					},
					Actions: []string{"pull", "push", "pull"},
				},
			},
			{
				"repository::pull",
				auth.Scope{
					Resource: auth.Resource{
						Type:  "repository",
						Class: "",
						Name:  "",
					},
					Actions: []string{"pull"},
				},
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run("", func(t *testing.T) {
				actual, err := auth.ParseScope(testCase.scope)
				require.NoError(t, err)

				assert.Equal(t, testCase.expected, actual)
			})
		}
	})

	t.Run("Error", func(t *testing.T) {
		testCases := []string{
			"repository : path/to/repo : pull , push ",
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run("", func(t *testing.T) {
				_, err := auth.ParseScope(testCase)
				require.Error(t, err)
			})
		}
	})
}

func TestScope_String(t *testing.T) {
	testCases := []struct {
		scope    auth.Scope
		expected string
	}{
		{
			auth.Scope{
				Resource: auth.Resource{
					Type:  "repository",
					Class: "",
					Name:  "path/to/repo",
				},
				Actions: []string{"pull", "push"},
			},
			"repository:path/to/repo:pull,push",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run("", func(t *testing.T) {
			actual := testCase.scope.String()

			assert.Equal(t, testCase.expected, actual)
		})
	}
}

func TestParseScopes(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		testCases := []struct {
			scopes   []string
			expected []auth.Scope
		}{
			{
				nil,
				nil,
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run("", func(t *testing.T) {
				actual, err := auth.ParseScopes(testCase.scopes)
				require.NoError(t, err)

				assert.Equal(t, testCase.expected, actual)
			})
		}
	})
}
