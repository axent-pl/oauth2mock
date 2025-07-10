package sessionservice

import "sync"

// sessionMemoryService is an in-memory implementation of SessionService.
// It uses a sync.RWMutex to allow concurrent safe access to the session data.
type sessionMemoryService struct {
	dataMU sync.RWMutex
	data   map[string]SessionData
}

// NewSessionMemoryService creates and returns a new in-memory session service.
// The service holds session data in a Go map protected by a read-write mutex.
//
// Currently, this function always returns a non-nil error value (nil), but
// the signature reserves the possibility of returning an error in future
// implementations (for example, if initialization fails).
func NewSessionMemoryService() (SessionService, error) {
	s := &sessionMemoryService{
		data: make(map[string]SessionData),
	}
	return s, nil
}

// Get retrieves the session data for the specified sessionID.
// If the sessionID does not exist, the returned boolean is false.
func (s *sessionMemoryService) Get(sessionID string) (SessionData, bool) {
	s.dataMU.RLock()
	defer s.dataMU.RUnlock()
	d, ok := s.data[sessionID]
	return d, ok
}

// Put stores or updates the session data for the specified sessionID.
// This method acquires a write lock to ensure safe concurrent writes.
func (s *sessionMemoryService) Put(sessionID string, data SessionData) {
	s.dataMU.Lock()
	defer s.dataMU.Unlock()
	s.data[sessionID] = data
}
