
Please review and recommend improvements for the following code.
It is a user service which might be initiated with different providers based on the definition in a JSON config file.

```golang
// pkg/service/user/provider.go
package userservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Configurable interface for construction of UserServicer from configuration
type Configurable interface {
	Init() (UserServicer, error)
}

// map of registered UserServicer sources
var userServiceProviderRegistryMu sync.RWMutex
var userServiceProviderRegistry = make(map[string]func() Configurable)

// register provider constructor
func RegisterUserServiceProvider(name string, constructor func() Configurable) {
	userServiceProviderRegistryMu.Lock()
	defer userServiceProviderRegistryMu.Unlock()
	userServiceProviderRegistry[name] = constructor
}

// return provider based on the configuration key
func ProviderFromJSONRawMessage(providerConfig map[string]json.RawMessage) (Configurable, error) {
	for name, rawProvider := range providerConfig {
		constructor, ok := userServiceProviderRegistry[name]
		if !ok {
			return nil, fmt.Errorf("unsupported user service provider type: %s", name)
		}
		instance := constructor()
		if err := json.Unmarshal(rawProvider, instance); err != nil {
			return nil, fmt.Errorf("failed to unmarshal %s provider: %w", name, err)
		}
		return instance, nil
	}
	return nil, errors.New("no provider")
}
```
```golang
// pkg/service/user/config.go
package userservice

import (
	"encoding/json"
)

type UserServiceConfig struct {
	Provider Configurable `json:"provider"`
}

func (cfg *UserServiceConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Provider map[string]json.RawMessage `json:"provider"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	provider, err := ProviderFromJSONRawMessage(raw.Provider)
	if err != nil {
		return err
	}
	cfg.Provider = provider

	return nil
}
```
```golang
// pkg/service/user/userhandler.go
package userservice

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type userHandler struct {
	id           string
	name         string
	active       bool
	authScheme   authentication.SchemeHandler
	customFields map[string]map[string]interface{}
}

type UserHandlerOption func(*userHandler) error

func NewUserHandler(id string, authScheme authentication.SchemeHandler, options ...UserHandlerOption) (UserHandler, error) {
	user := &userHandler{
		id:           id,
		name:         id, // default name equals ID unless overridden
		active:       true,
		authScheme:   authScheme,
		customFields: make(map[string]map[string]interface{}),
	}

	for _, opt := range options {
		if err := opt(user); err != nil {
			return nil, err
		}
	}

	return user, nil
}

func (s *userHandler) Id() string {
	return s.id
}

func (s *userHandler) Name() string {
	return s.name
}

func (s *userHandler) SetName(name string) {
	s.name = name
}

func (s *userHandler) Active() bool {
	return s.active
}

func (s *userHandler) SetActive(active bool) {
	s.active = active
}

func (s *userHandler) AuthenticationScheme() authentication.SchemeHandler {
	return s.authScheme
}

func (s *userHandler) SetAuthenticationScheme(scheme authentication.SchemeHandler) {
	s.authScheme = scheme
}

func (s *userHandler) GetCustomAttributes(key string) map[string]interface{} {
	if value, ok := s.customFields[key]; ok {
		return value
	}
	return nil
}

func (s *userHandler) SetCustomAttributes(key string, value map[string]interface{}) {
	if value == nil {
		return
	}
	if s.customFields == nil {
		s.customFields = make(map[string]map[string]interface{})
	}
	s.customFields[key] = value
}

func WithName(name string) UserHandlerOption {
	return func(u *userHandler) error {
		u.name = name
		return nil
	}
}

func WithActive(active bool) UserHandlerOption {
	return func(u *userHandler) error {
		u.active = active
		return nil
	}
}

func WithCustomAttributes(key string, value map[string]interface{}) UserHandlerOption {
	return func(u *userHandler) error {
		u.SetCustomAttributes(key, value)
		return nil
	}
}
```
```golang
// pkg/service/user/userservice.go
package userservice

import (
	"encoding/json"
	"fmt"
	"os"
)

func NewUserService(jsonFilepath string) (UserServicer, error) {
	type jsonConfigStruct struct {
		Config UserServiceConfig `json:"users"`
	}
	f := jsonConfigStruct{}

	data, err := os.ReadFile(jsonFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read user service config file: %w", err)
	}

	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse user service config file: %w", err)
	}

	userService, err := f.Config.Provider.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize user service: %w", err)
	}

	return userService, nil
}
```
```golang
// pkg/service/user/interface.go
package userservice

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type UserHandler interface {
	Id() string
	Name() string
	SetName(string)
	Active() bool
	SetActive(bool)
	AuthenticationScheme() authentication.SchemeHandler
	SetAuthenticationScheme(authentication.SchemeHandler)

	GetCustomAttributes(key string) map[string]interface{}
	SetCustomAttributes(key string, value map[string]interface{})
}

type UserServicer interface {
	Authenticate(credentials authentication.CredentialsHandler) (UserHandler, error)
	GetUsers() ([]UserHandler, error)
	AddUser(UserHandler) error
}
```
```golang
// pkg/service/user/providerfromdb.go
package userservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
	_ "github.com/lib/pq"
)

type FromDBConfig struct {
	Driver   string            `json:"driver"`
	User     string            `json:"user"`
	Password string            `json:"password"`
	Host     string            `json:"host"`
	Port     string            `json:"port"`
	Database string            `json:"database"`
	Options  map[string]string `json:"options"`
}

type userDBService struct {
	db *sql.DB
}

func (c *FromDBConfig) Init() (UserServicer, error) {
	if c.Driver != "postgres" {
		return nil, errors.New("unsupported driver")
	}
	connectionString := fmt.Sprintf("%s://%s:%s@%s:%s/%s?sslmode=disable", c.Driver, c.User, c.Password, c.Host, c.Port, c.Database)
	db, err := sql.Open(c.Driver, connectionString)
	if err != nil {
		return nil, err
	}
	return NewUserDBService(db)
}

func NewUserDBService(db *sql.DB) (UserServicer, error) {
	return &userDBService{db: db}, nil
}

func (s *userDBService) Authenticate(creds authentication.CredentialsHandler) (UserHandler, error) {
	username, err := creds.IdentityName()
	if err != nil {
		return nil, err
	}

	var password string
	var active bool
	var customAttrsBytes []byte

	query := `SELECT password, active, custom_attributes FROM users WHERE username = $1`
	err = s.db.QueryRowContext(context.Background(), query, username).Scan(&password, &active, &customAttrsBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.ErrUserCredsInvalid
		}
		return nil, err
	}

	authScheme, err := authentication.NewScheme(authentication.WithUsernameAndPassword(username, password))
	if err != nil {
		return nil, fmt.Errorf("invalid stored credentials: %w", err)
	}

	if !authScheme.Matches(creds) {
		return nil, errs.ErrUserCredsInvalid
	}

	user, err := NewUserHandler(username, authScheme, WithActive(active))
	if err != nil {
		return nil, err
	}

	var custom map[string]map[string]interface{}
	if err := json.Unmarshal(customAttrsBytes, &custom); err == nil {
		for k, v := range custom {
			user.SetCustomAttributes(k, v)
		}
	}

	return user, nil
}

func (s *userDBService) GetUsers() ([]UserHandler, error) {
	query := `SELECT username, password, active, custom_attributes FROM users`

	rows, err := s.db.QueryContext(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserHandler

	for rows.Next() {
		var username, password string
		var active bool
		var customAttrsBytes []byte

		if err := rows.Scan(&username, &password, &active, &customAttrsBytes); err != nil {
			return nil, err
		}

		authScheme, err := authentication.NewScheme(authentication.WithUsernameAndPassword(username, password))
		if err != nil {
			return nil, err
		}

		user, err := NewUserHandler(username, authScheme, WithActive(active))
		if err != nil {
			return nil, err
		}

		var custom map[string]map[string]interface{}
		if err := json.Unmarshal(customAttrsBytes, &custom); err == nil {
			for k, v := range custom {
				user.SetCustomAttributes(k, v)
			}
		}

		users = append(users, user)
	}

	return users, nil
}

func (s *userDBService) AddUser(user UserHandler) error {
	username := user.Name()

	var exists bool
	err := s.db.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, username).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("user already exists")
	}

	pw := ""
	if scheme := user.AuthenticationScheme(); scheme != nil {
		pw = scheme.PasswordHash()
	}

	customAttrs := user.(*userHandler).customFields
	customAttrsJSON, err := json.Marshal(customAttrs)
	if err != nil {
		return fmt.Errorf("failed to encode custom attributes: %w", err)
	}

	_, err = s.db.ExecContext(context.Background(),
		`INSERT INTO users (username, password, active, custom_attributes) VALUES ($1, $2, $3, $4)`,
		username, pw, user.Active(), customAttrsJSON)

	return err
}

func init() {
	RegisterUserServiceProvider("fromDB", func() Configurable { return &FromDBConfig{} })
}
```
```golang
// pkg/service/user/providerfromjson.go
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
			return nil, fmt.Errorf("failed to parse user credentials for '%s': %w", username, err)
		}
		user, err := NewUserHandler(username, authScheme)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize user '%s': %w", username, err)
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
	RegisterUserServiceProvider("fromJSON", func() Configurable { return &FromJSONConfig{} })
}
```
