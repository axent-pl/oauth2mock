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
		return nil, err
	}
	if config.Driver != "postgres" {
		return nil, errors.New("unsupported driver")
	}
	connectionString := fmt.Sprintf("%s://%s:%s@%s:%s/%s?sslmode=disable", config.Driver, config.User, config.Password, config.Host, config.Port, config.Database)
	db, err := sql.Open(config.Driver, connectionString)
	if err != nil {
		return nil, err
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

	user := databaseUserHandler{
		userHandler{
			id:           username,
			name:         username,
			active:       true,
			authScheme:   authScheme,
			customFields: make(map[string]map[string]interface{}),
		},
	}

	var custom map[string]map[string]interface{}
	if err := json.Unmarshal(customAttrsBytes, &custom); err == nil {
		for k, v := range custom {
			user.SetCustomAttributes(k, v)
		}
	}

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
		var customAttrsBytes []byte

		if err := rows.Scan(&username, &password, &active, &customAttrsBytes); err != nil {
			return nil, err
		}

		authScheme, err := authentication.NewScheme(authentication.WithUsernameAndPassword(username, password))
		if err != nil {
			return nil, err
		}

		user := jsonUserHandler{
			userHandler{
				id:           username,
				name:         username,
				active:       active,
				authScheme:   authScheme,
				customFields: make(map[string]map[string]interface{}),
			},
		}

		var custom map[string]map[string]interface{}
		if err := json.Unmarshal(customAttrsBytes, &custom); err == nil {
			for k, v := range custom {
				user.SetCustomAttributes(k, v)
			}
		}

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
		return err
	}
	if exists {
		return errors.New("user already exists")
	}

	pw := ""
	if scheme := user.AuthenticationScheme(); scheme != nil {
		pw = scheme.PasswordHash()
	}

	customAttrs := user.(*databaseUserHandler).customFields
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
	Register("database", NewDatabaseUserService)
}
