package auth

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
)

type subjectStub struct {
	id    SubjectID
	attrs map[string]string
}

// ID implements auth.Subject.
func (s subjectStub) ID() SubjectID {
	return s.id
}

// Attribute implements auth.Subject.
func (s subjectStub) Attribute(key string) (string, bool) {
	v, ok := s.attrs[key]

	return v, ok
}

// Attributes implements auth.Subject.
func (s subjectStub) Attributes() map[string]string {
	return maps.Clone(s.attrs)
}

func TestGetSubjectName(t *testing.T) {
	t.Run("ID", func(t *testing.T) {
		const id = "id"

		s := subjectStub{
			id: id,
		}

		subjectName := GetSubjectName(s)

		assert.Equal(t, id, subjectName)
	})

	t.Run("NameAttribute", func(t *testing.T) {
		const id = "id"
		const name = "name"

		s := subjectStub{
			id: id,
			attrs: map[string]string{
				SubjectName: name,
			},
		}

		subjectName := GetSubjectName(s)

		assert.Equal(t, name, subjectName)
	})
}
