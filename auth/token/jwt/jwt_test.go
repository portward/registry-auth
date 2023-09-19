package jwt

import (
	"maps"

	"github.com/portward/registry-auth/auth"
)

type subjectStub struct {
	id    auth.SubjectID
	attrs map[string]any
}

// ID implements auth.Subject.
func (s subjectStub) ID() auth.SubjectID {
	return s.id
}

// Attribute implements auth.Subject.
func (s subjectStub) Attribute(key string) (any, bool) {
	v, ok := s.attrs[key]

	return v, ok
}

// Attributes implements auth.Subject.
func (s subjectStub) Attributes() map[string]any {
	return maps.Clone(s.attrs)
}
