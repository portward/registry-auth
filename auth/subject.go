package auth

// SubjectID is the primary identifier of a Subject (a username or an arbitrary ID (eg. UUID)),
// but it is not necessarily globally unique: authenticators can federate between various providers and/or subject types (eg. human vs machine users).
// Therefore, SubjectID alone SHOULD NOT be used as a reference to the Subject if uniqueness cannot be guaranteed across the federated providers.
// The amount of information necessary to compose a key is an implementation/configuration detail,
// but the ID, the type of subject (if any) and the provider (if any) are generally enough to compose a globally (ie. across all providers) unique key.
//
// SubjectID appears in the "sub" claim of JWTs issued as access tokens.
type SubjectID interface {
	String() string
	Equals(other SubjectID) bool
}

// SubjectIDFromString returns a new [SubjectID] constructed from a string.
func SubjectIDFromString(id string) SubjectID {
	return subjectID(id)
}

type subjectID string

func (s subjectID) String() string {
	return string(s)
}

func (s subjectID) Equals(other SubjectID) bool {
	return string(s) == other.String()
}

// Subject contains information about the authenticated subject.
// For most (authorization) use cases, the information provided by Subject should be enough.
// However, custom implementations may provide additional behavior to help authorization decisions.
// That being said, it's up to the integrator to make sure all authenticators are compatible with such implementations.
type Subject interface {
	// ID returns the identifier of the Subject.
	ID() SubjectID

	// Attribute returns an attribute value and a boolean flag that shows whether the value exists or not.
	Attribute(key string) (string, bool)

	// Attributes are arbitrary key-value pairs that helps an Authorizer to make authorization decisions.
	//
	// Attributes MAY return a copy of it's internal map to avoid modifications.
	// As a result, it MAY be a relatively expensive operation and SHOULD only be used when necessary.
	// Prefer using Attribute instead.
	Attributes() map[string]string
}
