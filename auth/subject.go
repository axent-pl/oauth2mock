package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

type User struct {
	Username string
	Password string
}

type Subject struct {
	Name        string
	Credentials CredentialsService
}

// ----------------------------------------------------------------------------

type SubjectStorer interface {
	Authenticate(credentials CredentialsService) (*Subject, error)
}

// ----------------------------------------------------------------------------

type SubjectSimpleStorer struct {
	subjects map[string]Subject
}

func NewSubjectSimpleStorer(subjectsFile string) (*SubjectSimpleStorer, error) {
	type jsonUserStruct struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type jsonStoreStruct struct {
		Users map[string]jsonUserStruct `json:"users"`
	}

	f := jsonStoreStruct{}

	data, err := os.ReadFile(subjectsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read subjects config file: %w", err)
	}

	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse subjects config file: %w", err)
	}

	subjectStore := SubjectSimpleStorer{
		subjects: make(map[string]Subject),
	}

	for username, userData := range f.Users {
		credentials, err := NewCredentials(WithUsernameAndPassword(userData.Username, userData.Password))
		if err != nil {
			panic(fmt.Errorf("failed to parse user credentials from config file: %w", err))
		}
		subjectStore.subjects[username] = Subject{
			Name:        userData.Username,
			Credentials: credentials,
		}
	}

	return &subjectStore, nil
}

func (s *SubjectSimpleStorer) Authenticate(credentials CredentialsService) (*Subject, error) {
	for _, subject := range s.subjects {
		if credentials.Match(subject.Credentials) {
			return &subject, nil
		}
	}
	return nil, ErrInvalidCreds
}
