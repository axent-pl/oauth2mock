
Given the golang package code please implement a functionality which will check if ther users table
is created, has the correct schema and if not will apply required DDL.

```golang
// pkg/service/user/factory.go
package userservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

type UserServiceFactory func(json.RawMessage) (UserServicer, error)

var (
	userServiceFactoryRegistryMU sync.RWMutex
	userServiceFactoryRegistry   = map[string]UserServiceFactory{}
)

func Register(name string, f UserServiceFactory) {
	userServiceFactoryRegistryMU.Lock()
	defer userServiceFactoryRegistryMU.Unlock()
	userServiceFactoryRegistry[name] = f
}

type Config struct {
	UsersConfig json.RawMessage `json:"users"`
}

func NewFromConfig(rawConfig []byte) (UserServicer, error) {
	config := Config{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, errors.New("failed to unmarshal config")
	}

	var usersMap map[string]json.RawMessage
	if err := json.Unmarshal(config.UsersConfig, &usersMap); err != nil {
		return nil, errors.New("failed to parse users config")
	}

	providerRaw, ok := usersMap["provider"]
	if !ok {
		return nil, errors.New("missing users.provider")
	}

	var provider string
	if err := json.Unmarshal(providerRaw, &provider); err != nil {
		return nil, errors.New("invalid users.provider")
	}

	userServiceFactoryRegistryMU.RLock()
	factory, ok := userServiceFactoryRegistry[provider]
	userServiceFactoryRegistryMU.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown user service provider: %s", provider)
	}

	return factory(config.UsersConfig)
}
```
```golang
// pkg/service/user/userhandler.go
package userservice

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type userHandler struct {
	id         string
	name       string
	active     bool
	authScheme authentication.SchemeHandler
	attributes map[string]map[string]interface{}
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

func (s *userHandler) GetAllAttributes() map[string]map[string]interface{} {
	return s.attributes
}

func (s *userHandler) SetAllAttributes(attributes map[string]map[string]interface{}) {
	s.attributes = attributes
}

func (s *userHandler) GetAttributesGroup(key string) map[string]interface{} {
	if value, ok := s.attributes[key]; ok {
		return value
	}
	return nil
}

func (s *userHandler) SetAttributesGroup(key string, value map[string]interface{}) {
	if value == nil {
		return
	}
	if s.attributes == nil {
		s.attributes = make(map[string]map[string]interface{})
	}
	s.attributes[key] = value
}

func NewUserHandler(id string, authScheme authentication.SchemeHandler, options ...UserHandlerOption) (UserHandler, error) {
	user := &userHandler{
		id:         id,
		name:       id, // default name equals ID unless overridden
		active:     true,
		authScheme: authScheme,
		attributes: make(map[string]map[string]interface{}),
	}

	for _, opt := range options {
		if err := opt(user); err != nil {
			return nil, err
		}
	}

	return user, nil
}

type UserHandlerOption func(*userHandler) error

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
		u.SetAttributesGroup(key, value)
		return nil
	}
}
```
```golang
// pkg/service/user/jsonuserservice.go
package userservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	e "github.com/axent-pl/oauth2mock/pkg/errs"
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

func NewJSONUserService(rawConfig json.RawMessage) (UserServicer, error) {
	config := jsonUserServiceConfig{}
	userService := jsonUserService{
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

	return &userService, nil
}

func (s *jsonUserService) Authenticate(inputCredentials authentication.CredentialsHandler) (UserHandler, error) {
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
		return &user, nil
	}

	return nil, e.ErrUserCredsInvalid
}

func (s *jsonUserService) GetUsers() ([]UserHandler, error) {
	var users []UserHandler = make([]UserHandler, 0)
	for _, k := range s.users {
		users = append(users, &k)
	}
	return users, nil
}

func (s *jsonUserService) AddUser(user UserHandler) error {
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
```
```golang
// pkg/service/user/databaseuserservice.go
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

type databaseUserServiceConfig struct {
	Provider string            `json:"provider"`
	Driver   string            `json:"driver"`
	User     string            `json:"user"`
	Password string            `json:"password"`
	Host     string            `json:"host"`
	Port     string            `json:"port"`
	Database string            `json:"database"`
	Options  map[string]string `json:"options"`
}

type databaseUserHandler struct {
	userHandler
}

type databaseUserService struct {
	db *sql.DB
}

func NewDatabaseUserService(rawConfig json.RawMessage) (UserServicer, error) {
	config := databaseUserServiceConfig{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user service config: %w", err)
	}
	if config.Driver != "postgres" {
		return nil, fmt.Errorf("unsupported user service database driver: %s", config.Driver)
	}
	connectionString := fmt.Sprintf("%s://%s:%s@%s:%s/%s?sslmode=disable", config.Driver, config.User, config.Password, config.Host, config.Port, config.Database)
	db, err := sql.Open(config.Driver, connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open user service database connection: %w", err)
	}
	return NewUserDBService(db)
}

func NewUserDBService(db *sql.DB) (UserServicer, error) {
	return &databaseUserService{db: db}, nil
}

func (s *databaseUserService) Authenticate(creds authentication.CredentialsHandler) (UserHandler, error) {
	username, err := creds.IdentityName()
	if err != nil {
		return nil, err
	}

	var password string
	var active bool
	var attributesBytes []byte
	var attributes map[string]map[string]interface{}

	query := `SELECT password, active, custom_attributes FROM users WHERE username = $1`
	err = s.db.QueryRowContext(context.Background(), query, username).Scan(&password, &active, &attributesBytes)
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

	user := databaseUserHandler{
		userHandler{
			id:         username,
			name:       username,
			active:     true,
			authScheme: authScheme,
			attributes: make(map[string]map[string]interface{}),
		},
	}

	if err := json.Unmarshal(attributesBytes, &attributes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user attributes: %w", err)
	}
	user.SetAllAttributes(attributes)

	return &user, nil
}

func (s *databaseUserService) GetUsers() ([]UserHandler, error) {
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
		var attributesBytes []byte
		var attributes map[string]map[string]interface{}

		if err := rows.Scan(&username, &password, &active, &attributesBytes); err != nil {
			return nil, err
		}

		authScheme, err := authentication.NewScheme(authentication.WithUsernameAndPassword(username, password))
		if err != nil {
			return nil, err
		}

		user := jsonUserHandler{
			userHandler{
				id:         username,
				name:       username,
				active:     active,
				authScheme: authScheme,
				attributes: make(map[string]map[string]interface{}),
			},
		}

		if err := json.Unmarshal(attributesBytes, &attributes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal user attributes: %w", err)
		}
		user.SetAllAttributes(attributes)

		users = append(users, &user)
	}

	return users, nil
}

func (s *databaseUserService) AddUser(user UserHandler) error {
	username := user.Name()

	var exists bool
	err := s.db.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to execute user select exists query: %w", err)
	}
	if exists {
		return fmt.Errorf("failed to add user, user %s already exists", username)
	}

	pw := ""
	if scheme := user.AuthenticationScheme(); scheme != nil {
		pw = scheme.PasswordHash()
	}

	attributes := user.GetAllAttributes()
	attributesJSON, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("failed to encode custom attributes: %w", err)
	}

	_, err = s.db.ExecContext(context.Background(),
		`INSERT INTO users (username, password, active, custom_attributes) VALUES ($1, $2, $3, $4)`,
		username, pw, user.Active(), attributesJSON)

	return err
}

func init() {
	Register("database", NewDatabaseUserService)
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
	GetAllAttributes() map[string]map[string]interface{}
	SetAllAttributes(map[string]map[string]interface{})
	GetAttributesGroup(group string) map[string]interface{}
	SetAttributesGroup(group string, value map[string]interface{})
}

type UserServicer interface {
	Authenticate(credentials authentication.CredentialsHandler) (UserHandler, error)
	GetUsers() ([]UserHandler, error)
	AddUser(UserHandler) error
}
```
