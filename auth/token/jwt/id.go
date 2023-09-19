package jwt

import "github.com/gofrs/uuid"

// IDGenerator generates a random ID.
type IDGenerator interface {
	GenerateID() (string, error)
}

type uuidGenerator struct{}

func (g uuidGenerator) GenerateID() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	return u.String(), nil
}
