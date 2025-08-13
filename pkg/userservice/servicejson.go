package userservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/axent-pl/oauth2mock/pkg/di"
	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
)

type jsonUserServiceConfig struct {
	Provider string `json:"provider"`
	Users    map[string]struct {
		Username   string                            `json:"username"`
		Password   string                            `json:"password"`
		Attributes map[string]map[string]interface{} `json:"attributes"`
	} `json:"users"`
}

type jsonUserHandler struct {
	userHandler
}

type jsonUserService struct {
	users   map[string]jsonUserHandler
	usersMU sync.RWMutex
}

func NewJSONUserService(rawConfig json.RawMessage) (Service, error) {
	config := jsonUserServiceConfig{}
	userService := &jsonUserService{
		users: make(map[string]jsonUserHandler),
	}

	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, err
	}

	for username, userData := range config.Users {
		authScheme, err := authentication.NewScheme(authentication.WithUsernameAndPassword(userData.Username, userData.Password))
		if err != nil {
			return nil, fmt.Errorf("failed to parse user credentials for '%s': %w", username, err)
		}
		user := jsonUserHandler{
			userHandler{
				id:         username,
				name:       username,
				active:     true,
				authScheme: authScheme,
				attributes: userData.Attributes,
			},
		}
		userService.users[username] = user
	}

	di.Register(userService)

	return userService, nil
}

func (s *jsonUserService) Authenticate(inputCredentials authentication.CredentialsHandler) (Entity, error) {
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
		return nil, errs.ErrUserCredsInvalid
	}

	// check if credentials match
	if user.AuthenticationScheme().Matches(inputCredentials) {
		return &user, nil
	}

	return nil, errs.ErrUserCredsInvalid
}

func (s *jsonUserService) GetUsers() ([]Entity, error) {
	var users []Entity = make([]Entity, 0)
	for _, k := range s.users {
		users = append(users, &k)
	}
	return users, nil
}

func (s *jsonUserService) GetUser(username string) (Entity, error) {
	user, ok := s.users[username]
	if ok {
		return &user, nil
	}
	return nil, errors.New("user does not exist")
}

func (s *jsonUserService) AddUser(user Entity) error {
	s.usersMU.RLock()
	defer s.usersMU.RUnlock()

	username := user.Name()

	if _, ok := s.users[username]; ok {
		return errors.New("user already exists")
	}

	s.users[username] = jsonUserHandler{
		userHandler{
			id:         user.Id(),
			name:       user.Name(),
			active:     user.Active(),
			authScheme: user.AuthenticationScheme(),
			attributes: user.GetAllAttributes(),
		},
	}

	return nil
}

func init() {
	Register("json", NewJSONUserService)
}
