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
						Type: "repository",
						Name: "path/to/repo",
					},
					Actions: []string{"pull", "push"},
				},
			},
			{
				"repository:path/to/repo: pull , push ",
				auth.Scope{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo",
					},
					Actions: []string{"pull", "push"},
				},
			},
			{
				"repository(class):path/to/repo:pull",
				auth.Scope{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo",
					},
					Actions: []string{"pull"},
				},
			},
			{
				"repository:path/to/repo:pull,push,pull", // duplicates are allowed for now
				auth.Scope{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo",
					},
					Actions: []string{"pull", "push", "pull"},
				},
			},
			{
				"repository::pull",
				auth.Scope{
					Resource: auth.Resource{
						Type: "repository",
						Name: "",
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

func TestScope_CompareAndEquals(t *testing.T) {
	testCases := []struct {
		x        auth.Scope
		y        auth.Scope
		expected int
	}{
		{
			auth.Scope{},
			auth.Scope{},
			0,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
				},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
				},
			},
			0,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
			},
			0,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"pull", "push"},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"pull", "push"},
			},
			0,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"push", "pull"},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"pull", "push"},
			},
			0,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "a",
				},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "b",
				},
			},
			-1,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "b",
				},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "a",
				},
			},
			1,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "a",
				},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "b",
				},
			},
			-1,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "b",
				},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "a",
				},
			},
			1,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"pull"},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"push"},
			},
			-1,
		},
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"push"},
			},
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
				},
				Actions: []string{"pull"},
			},
			1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run("", func(t *testing.T) {
			actual := testCase.x.Compare(testCase.y)

			assert.Equal(t, testCase.expected, actual)

			if testCase.expected == 0 {
				assert.True(t, testCase.x.Equals(testCase.y))
			} else {
				assert.False(t, testCase.x.Equals(testCase.y))
			}
		})
	}
}

func TestScope_String(t *testing.T) {
	testCases := []struct {
		scope    auth.Scope
		expected string
	}{
		{
			auth.Scope{
				Resource: auth.Resource{
					Type: "repository",
					Name: "path/to/repo",
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

func TestScopes_CompareAndEquals(t *testing.T) {
	testCases := []struct {
		x        auth.Scopes
		y        auth.Scopes
		expected int
	}{
		{
			auth.Scopes{},
			auth.Scopes{},
			0,
		},
		{
			auth.Scopes{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo",
					},
					Actions: []string{"pull", "push"},
				},
			},
			auth.Scopes{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo",
					},
					Actions: []string{"push", "pull"},
				},
			},
			0,
		},
		{
			auth.Scopes{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo-a",
					},
					Actions: []string{"pull", "push"},
				},
			},
			auth.Scopes{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo-b",
					},
					Actions: []string{"pull", "push"},
				},
			},
			-1,
		},
		{
			auth.Scopes{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo-b",
					},
					Actions: []string{"pull", "push"},
				},
			},
			auth.Scopes{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "path/to/repo-a",
					},
					Actions: []string{"pull", "push"},
				},
			},
			1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run("", func(t *testing.T) {
			actual := testCase.x.Compare(testCase.y)

			assert.Equal(t, testCase.expected, actual)

			if testCase.expected == 0 {
				assert.True(t, testCase.x.Equals(testCase.y))
			} else {
				assert.False(t, testCase.x.Equals(testCase.y))
			}
		})
	}
}

func TestScopes_String(t *testing.T) {
	scopes := auth.Scopes{
		{
			Resource: auth.Resource{
				Type: "repository",
				Name: "path/to/repo-a",
			},
			Actions: []string{"pull", "push"},
		},
		{
			Resource: auth.Resource{
				Type: "repository",
				Name: "path/to/repo-b",
			},
			Actions: []string{"pull", "push"},
		},
	}

	const expected = "repository:path/to/repo-a:pull,push repository:path/to/repo-b:pull,push"

	assert.Equal(t, expected, scopes.String())
}
