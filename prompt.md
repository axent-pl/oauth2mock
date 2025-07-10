
Given the golang package code please review it and add documentation.

```golang
// pkg/sessionservice/interface.go
package sessionservice

type SessionService interface {
	Get(string) (SessionData, bool)
	Put(string, SessionData)
}
```
```golang
// pkg/sessionservice/model.go
package sessionservice

type SessionData map[string]any
```
```golang
// pkg/sessionservice/servicememory.go
package sessionservice

import "sync"

type sessionMemoryService struct {
	dataMU sync.RWMutex
	data   map[string]SessionData
}

func NewSessionMemoryService() (SessionService, error) {
	s := &sessionMemoryService{
		data: make(map[string]SessionData),
	}
	return s, nil
}

func (s *sessionMemoryService) Get(sessionID string) (SessionData, bool) {
	s.dataMU.RLock()
	defer s.dataMU.RUnlock()
	d, ok := s.data[sessionID]
	return d, ok
}

func (s *sessionMemoryService) Put(sessionID string, data SessionData) {
	s.dataMU.Lock()
	defer s.dataMU.Unlock()
	s.data[sessionID] = data
}
```
