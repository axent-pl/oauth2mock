package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	e "github.com/axent-pl/oauth2mock/pkg/error"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
)

type UserServicer interface {
	Authenticate(credentials authentication.CredentialsHandler) (UserHandler, error)
	GetUsers() ([]UserHandler, error)
}

type userService struct {
	users   map[string]userHandler
	usersMU sync.RWMutex
}

func NewUserService(usersFile string) (UserServicer, error) {
	var rawData struct {
		Users map[string]struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"users"`
	}

	reader, err := os.Open(usersFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read users config file: %w", err)
	}

	if err := json.NewDecoder(reader).Decode(&rawData); err != nil {
		return nil, fmt.Errorf("failed to parse users config file: %w", err)
	}

	userStore := userService{
		users: make(map[string]userHandler),
	}

	for username, userData := range rawData.Users {
		credentials, err := authentication.NewScheme(authentication.WithUsernameAndPassword(userData.Username, userData.Password))
		if err != nil {
			panic(fmt.Errorf("failed to parse user credentials from config file: %w", err))
		}
		userStore.users[username] = userHandler{
			name:       userData.Username,
			authScheme: credentials,
		}
	}

	return &userStore, nil
}

func (s *userService) Authenticate(inputCredentials authentication.CredentialsHandler) (UserHandler, error) {
	s.usersMU.RLock()
	defer s.usersMU.RUnlock()

	// get user name from input credentials
	username, err := inputCredentials.IdentityName()
	if err != nil {
		return nil, err
	}

	// find user
	user, ok := s.users[username]
	if !ok {
		return nil, e.ErrUserCredsInvalid
	}

	// check if credentials match
	if user.authScheme.IsValid(inputCredentials) {
		return &user, nil
	}

	return nil, e.ErrUserCredsInvalid
}

func (s *userService) GetUsers() ([]UserHandler, error) {
	var users []UserHandler = make([]UserHandler, 0)
	for _, k := range s.users {
		users = append(users, &k)
	}
	return users, nil
}
