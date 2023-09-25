package auth

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	slicesx "github.com/portward/registry-auth/pkg/slices"
)

// Scopes is a list of [Scope] instances.
type Scopes []Scope

// Compare compares this with another instance of Scopes.
// It compares the values of each Scope
// and returns a value following the mechanics of [cmp.Compare].
//
// Note that the values of Scope.Actions are always cloned and sorted before comparison,
// so this is not a cheap operation.
func (s Scopes) Compare(other Scopes) int {
	return slices.CompareFunc(s, other, func(x Scope, y Scope) int {
		return x.Compare(y)
	})
}

// Equals returns true if the other instance equals to this one, otherwise it returns false.
func (s Scopes) Equals(other Scopes) bool {
	return s.Compare(other) == 0
}

func (s Scopes) String() string {
	// TODO: create a slices.MapToString??
	return strings.Join(slicesx.Map(s, func(s Scope) string { return s.String() }), " ")
}

// Scope describes an access request to a specific resource.
type Scope struct {
	Resource
	Actions []string `json:"actions"`
}

// Compare compares this with another instance of Scope.
// It compares the values of Resource and Actions (in this order)
// and returns a value following the mechanics of [cmp.Compare].
//
// Note that the values of Actions are always cloned and sorted before comparison,
// so this is not a cheap operation.
func (s Scope) Compare(other Scope) int {
	if result := s.Resource.Compare(other.Resource); result != 0 {
		return result
	}

	thisActions := slices.Clone(s.Actions)
	slices.Sort(thisActions)

	otherActions := slices.Clone(other.Actions)
	slices.Sort(otherActions)

	if result := slices.Compare(thisActions, otherActions); result != 0 {
		return result
	}

	return 0
}

// Equals returns true if the other instance equals to this one, otherwise it returns false.
func (s Scope) Equals(other Scope) bool {
	return s.Compare(other) == 0
}

func (s Scope) String() string {
	return fmt.Sprintf("%s:%s", s.Resource.String(), strings.Join(s.Actions, ","))
}

// Resource describes a resource by type and name.
type Resource struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// Compare compares this with another instance of Resource.
// It compares the values of Type and Name (in this order)
// and returns a value following the mechanics of [cmp.Compare].
func (r Resource) Compare(other Resource) int {
	if result := cmp.Compare(r.Type, other.Type); result != 0 {
		return result
	}

	if result := cmp.Compare(r.Name, other.Name); result != 0 {
		return result
	}

	return 0
}

// Equals returns true if the other instance equals to this one, otherwise it returns false.
func (r Resource) Equals(other Resource) bool {
	return r.Compare(other) == 0
}

func (r Resource) String() string {
	return fmt.Sprintf("%s:%s", r.Type, r.Name)
}

// ParseScopes calls ParseScope for each scope in the list.
// If any of the scopes is invalid, ParseScopes returns an empty slice and an error.
func ParseScopes(scopes []string) ([]Scope, error) {
	return slicesx.TryMap(scopes, ParseScope)
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

	resourceType, _ = splitResourceClass(resourceType)
	if resourceType == "" {
		return Scope{}, fmt.Errorf("invalid scope format: %q", scope)
	}

	return Scope{
		Resource: Resource{
			Type: resourceType,
			Name: resourceName,
		},
		Actions: slicesx.Map(strings.Split(actions, ","), strings.TrimSpace),
	}, nil
}

var resourceTypeRegexp = regexp.MustCompile(`^([a-z0-9]+)(\([a-z0-9]+\))?$`)

// splitResourceClass parses a resource name and extracts the resource class (if any).
//
// The resource class is deprecated; this is here for backwards compatibility reasons
// to allow parsing scopes with resource classes.
//
// Read more:
//   - https://github.com/distribution/distribution/pull/4061
//   - https://github.com/distribution/distribution/blob/main/docs/spec/auth/scope.md#resource-class
func splitResourceClass(t string) (string, string) {
	matches := resourceTypeRegexp.FindStringSubmatch(t)
	if len(matches) < 2 {
		return "", ""
	}

	if len(matches) == 2 || len(matches[2]) < 2 {
		return matches[1], ""
	}

	return matches[1], matches[2][1 : len(matches[2])-1]
}
