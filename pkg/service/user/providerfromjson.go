package userservice

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"

	e "github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
)

type FromJSONConfig struct {
	Users map[string]struct {
		Username   string                            `json:"username"`
		Password   string                            `json:"password"`
		Attributes map[string]map[string]interface{} `json:"attributes"`
	} `json:"users"`
}

type userService struct {
	users   map[string]UserHandler
	usersMU sync.RWMutex
}

func (c *FromJSONConfig) Init() (UserServicer, error) {
	return NewJSONUserService(c)
}

func NewJSONUserService(usersData *FromJSONConfig) (UserServicer, error) {
	slog.Info("initializing JSON user service")
	userStore := userService{
		users: make(map[string]UserHandler),
	}

	for username, userData := range usersData.Users {
		authScheme, err := authentication.NewScheme(authentication.WithUsernameAndPassword(userData.Username, userData.Password))
		if err != nil {
			panic(fmt.Errorf("failed to parse user credentials: %w", err))
		}
		user, err := NewUserHandler(username, authScheme)
		if err != nil {
			panic(fmt.Errorf("failed to initialize user: %w", err))
		}
		for k, v := range userData.Attributes {
			user.SetCustomAttributes(k, v)
		}
		userStore.users[username] = user
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
	if user.AuthenticationScheme().Matches(inputCredentials) {
		return user, nil
	}

	return nil, e.ErrUserCredsInvalid
}

func (s *userService) GetUsers() ([]UserHandler, error) {
	var users []UserHandler = make([]UserHandler, 0)
	for _, k := range s.users {
		users = append(users, k)
	}
	return users, nil
}

func (s *userService) AddUser(user UserHandler) error {
	s.usersMU.RLock()
	defer s.usersMU.RUnlock()

	username := user.Name()

	if _, ok := s.users[username]; ok {
		return errors.New("user already exists")
	}

	s.users[username] = user

	return nil
}

func init() {
	RegisterUserServiceProvider("fromJSON", func() UserServiceProvider { return &FromJSONConfig{} })
}
