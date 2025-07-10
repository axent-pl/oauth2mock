package sessionservice

// SessionData represents arbitrary key-value pairs stored in a session.
// Use a map of string to interface{} to allow any type of value.
//
// Example usage:
//
//	data := SessionData{"user_id": 42, "authenticated": true}
//
// Note: Values stored in SessionData should be serializable if the
// backing store requires persistence across process restarts.
type SessionData map[string]any
