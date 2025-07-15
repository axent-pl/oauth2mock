package sessionservice

// Service defines methods for retrieving and storing session data
// by a unique session identifier.
//
// Implementations may choose different storage backends (in-memory, database,
// distributed cache, etc.).
type Service interface {
	// Get retrieves the session data associated with the given sessionID.
	// It returns the SessionData and a boolean flag indicating whether the
	// session was found.
	Get(string) (SessionData, bool)

	// Put stores or updates the session data for the given sessionID.
	// If data already exists for the session, it will be overwritten.
	Put(string, SessionData)
}
