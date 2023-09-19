package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubjectID(t *testing.T) {
	id := SubjectIDFromString("id")
	other := SubjectIDFromString("id")

	assert.Equal(t, "id", id.String())
	assert.True(t, id.Equals(other))
}
