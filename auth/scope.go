package auth

import (
	"fmt"
	"strings"

	"github.com/portward/registry-auth/pkg/slices"
)

// Scopes is a list of [Scope] instances.
type Scopes []Scope

func (s Scopes) String() string {
	// TODO: create a slices.MapToString??
	return strings.Join(slices.Map(s, func(s Scope) string { return s.String() }), " ")
}

// Scope describes an access request to a specific resource.
type Scope struct {
	Resource
	Actions []string `json:"actions"`
}

func (s Scope) String() string {
	return fmt.Sprintf("%s:%s", s.Resource.String(), strings.Join(s.Actions, ","))
}

// Resource describes a resource by type and name.
type Resource struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

func (r Resource) String() string {
	return fmt.Sprintf("%s:%s", r.Type, r.Name)
}

// ParseScopes calls ParseScope for each scope in the list.
// If any of the scopes is invalid, ParseScopes returns an empty slice and an error.
func ParseScopes(scopes []string) ([]Scope, error) {
	return slices.TryMap(scopes, ParseScope)
}

// ParseScope parses a scope string into a formal structure according to the [Token Scope documentation].
//
// General scope format: resourceType[(resourceClass)]:resourceName:action[,action...]
//
// ParseScope returns an error if the scope format is invalid.
//
// [Token Scope documentation]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/scope.md
func ParseScope(scope string) (Scope, error) {
	parts := strings.SplitN(scope, ":", 3)

	if len(parts) != 3 {
		return Scope{}, fmt.Errorf("invalid scope format: %q", scope)
	}

	resourceType, resourceName, actions := parts[0], parts[1], parts[2]

	if actions == "" {
		return Scope{}, fmt.Errorf("invalid scope format: %q", scope)
	}

	return Scope{
		Resource: Resource{
			Type: resourceType,
			Name: resourceName,
		},
		Actions: slices.Map(strings.Split(actions, ","), strings.TrimSpace),
	}, nil
}
