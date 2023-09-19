package jwt

import "time"

// Clock provides an interface to accessing current time.
type Clock interface {
	Now() time.Time
}
