package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

const subjectsFile = "run/users.json"

type User struct {
	Username string
	Password string
}

type Subject struct {
	Name        string
	Credentials *Credentials
}

// ----------------------------------------------------------------------------

type SubjectStorerInterface interface {
	Authenticate(credentials Credentials) (*Subject, error)
}

// ----------------------------------------------------------------------------

type SubjectSimpleStorer struct {
	subjects map[string]Subject
}

func NewSubjectSimpleStorer() *SubjectSimpleStorer {
	type jsonClientStruct struct {
		Id          string `json:"client_id"`
		Secret      string `json:"client_secret"`
		RedirectURI string `json:"redirect_uri"`
	}
	type jsonUserStruct struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type jsonStoreStruct struct {
		Clients map[string]jsonClientStruct `json:"clients"`
		Users   map[string]jsonUserStruct   `json:"users"`
	}

	f := jsonStoreStruct{}

	data, err := os.ReadFile(subjectsFile)
	if err != nil {
		panic(fmt.Errorf("failed to read subjects config file: %w", err))
	}

	if err := json.Unmarshal(data, &f); err != nil {
		panic(fmt.Errorf("failed to parse subjects config file: %w", err))
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
	for client_id, clientData := range f.Clients {
		credentials, err := NewCredentials(WithClientIdAndSecret(clientData.Id, clientData.Secret))
		if err != nil {
			panic(fmt.Errorf("failed to parse client credentials from config file: %w", err))
		}
		subjectStore.subjects[client_id] = Subject{
			Name:        clientData.Id,
			Credentials: credentials,
		}
	}

	return &subjectStore
}

func (s *SubjectSimpleStorer) Authenticate(credentials Credentials) (*Subject, error) {
	if len(credentials.Username) == 0 {
		return nil, ErrMissingCredUsername
	}
	if len(credentials.Password) == 0 {
		return nil, ErrMissingCredPassword
	}
	for _, subject := range s.subjects {
		if credentials.Match(subject.Credentials) {
			return &subject, nil
		}
	}
	return nil, ErrInvalidCreds
}
