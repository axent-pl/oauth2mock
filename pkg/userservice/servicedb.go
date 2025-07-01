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

	Queries struct {
		GetUser    string `json:"get_user,omitempty"`
		GetUsers   string `json:"get_users,omitempty"`
		AddUser    string `json:"add_user,omitempty"`
		UserExists string `json:"user_exists,omitempty"`
	} `json:"queries,omitempty"`
}

type databaseUserHandler struct {
	userHandler
}

type databaseUserService struct {
	db      *sql.DB
	queries struct {
		GetUser    string
		GetUsers   string
		AddUser    string
		UserExists string
	}
}

func NewDatabaseUserService(rawConfig json.RawMessage) (UserServicer, error) {
	config := databaseUserServiceConfig{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user service config: %w", err)
	}
	if config.Driver != "postgres" {
		return nil, fmt.Errorf("unsupported user service database driver: %s", config.Driver)
	}

	connectionString := fmt.Sprintf("%s://%s:%s@%s:%s/%s?sslmode=disable",
		config.Driver, config.User, config.Password, config.Host, config.Port, config.Database)
	db, err := sql.Open(config.Driver, connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open user service database connection: %w", err)
	}

	svc := &databaseUserService{db: db}
	svc.queries.GetUser = config.Queries.GetUser
	if svc.queries.GetUser == "" {
		svc.queries.GetUser = `SELECT password, active, custom_attributes FROM users WHERE username = $1`
	}
	svc.queries.GetUsers = config.Queries.GetUsers
	if svc.queries.GetUsers == "" {
		svc.queries.GetUsers = `SELECT username, password, active, custom_attributes FROM users`
	}
	svc.queries.AddUser = config.Queries.AddUser
	if svc.queries.AddUser == "" {
		svc.queries.AddUser = `INSERT INTO users (username, password, active, custom_attributes) VALUES ($1, $2, $3, $4)`
	}
	svc.queries.UserExists = config.Queries.UserExists
	if svc.queries.UserExists == "" {
		svc.queries.UserExists = `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`
	}

	return svc, nil
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

	err = s.db.QueryRowContext(context.Background(), s.queries.GetUser, username).Scan(&password, &active, &attributesBytes)
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
	rows, err := s.db.QueryContext(context.Background(), s.queries.GetUsers)
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
	err := s.db.QueryRowContext(context.Background(), s.queries.UserExists, username).Scan(&exists)
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

	_, err = s.db.ExecContext(context.Background(), s.queries.AddUser, username, pw, user.Active(), attributesJSON)

	return err
}

func init() {
	Register("database", NewDatabaseUserService)
}
