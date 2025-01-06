package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

const subjectsFile = "run/clients.json"

type User struct {
	Username string
	Password string
}

type Subject struct {
	Name        string
	Credentials Credentials
}

type Credentials struct {
	Username       string
	Password       string
	ClientId       string
	ClientSecret   string
	AssertionToken string
}

func (c *Credentials) Valid() error {
	if c.Username == "bad" {
		return ErrInvalidCreds
	}
	return nil
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
	type fileStructure struct {
		Clients map[string]Client `json:"clients"`
		Users   map[string]User   `json:"users"`
	}
	f := fileStructure{}
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
		subjectStore.subjects[username] = Subject{
			Name: userData.Username,
			Credentials: Credentials{
				Username: userData.Username,
				Password: userData.Password,
			},
		}
	}
	for client_id, clientData := range f.Clients {
		subjectStore.subjects[client_id] = Subject{
			Name: clientData.Id,
			Credentials: Credentials{
				ClientId:     clientData.Id,
				ClientSecret: clientData.Secret,
			},
		}
	}

	return &subjectStore
}

func (s *SubjectSimpleStorer) Authenticate(credentials Credentials) (*Subject, error) {
	for _, subject := range s.subjects {
		if credentials.Username == subject.Credentials.Username && credentials.Password == subject.Credentials.Password {
			return &subject, nil
		}
	}
	return nil, ErrInvalidCreds
}
