package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type SubjectServicer interface {
	Authenticate(credentials CredentialsHandler) (SubjectHandler, error)
}

type subjectService struct {
	subjects   map[string]subject
	subjectsMU sync.RWMutex
}

func NewSubjectService(subjectsFile string) (SubjectServicer, error) {
	var rawData struct {
		Users map[string]struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"users"`
	}

	reader, err := os.Open(subjectsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read subjects config file: %w", err)
	}

	if err := json.NewDecoder(reader).Decode(&rawData); err != nil {
		return nil, fmt.Errorf("failed to parse subjects config file: %w", err)
	}

	subjectStore := subjectService{
		subjects: make(map[string]subject),
	}

	for username, userData := range rawData.Users {
		credentials, err := NewCredentials(WithUsernameAndPassword(userData.Username, userData.Password))
		if err != nil {
			panic(fmt.Errorf("failed to parse user credentials from config file: %w", err))
		}
		subjectStore.subjects[username] = subject{
			name:        userData.Username,
			credentials: credentials,
		}
	}

	return &subjectStore, nil
}

func (s *subjectService) Authenticate(credentials CredentialsHandler) (SubjectHandler, error) {
	s.subjectsMU.RLock()
	defer s.subjectsMU.RUnlock()

	for _, subject := range s.subjects {
		if credentials.Match(subject.credentials) {
			return &subject, nil
		}
	}
	return nil, ErrInvalidCreds
}
