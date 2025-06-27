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
	svc := &databaseUserService{db: db}
	if err := svc.ensureUserTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure users table schema: %w", err)
	}
	return svc, nil
}

func (s *databaseUserService) ensureUserTable() error {
	const expectedTable = "users"
	const checkQuery = `
		SELECT column_name, data_type
		FROM information_schema.columns
		WHERE table_name = $1
	`

	rows, err := s.db.QueryContext(context.Background(), checkQuery, expectedTable)
	if err != nil {
		return s.createUserTable()
	}
	defer rows.Close()

	// Map of expected schema
	expectedSchema := map[string]string{
		"username":          "text",
		"password":          "text",
		"active":            "boolean",
		"custom_attributes": "jsonb",
	}

	foundColumns := make(map[string]string)
	for rows.Next() {
		var col, dtype string
		if err := rows.Scan(&col, &dtype); err != nil {
			return fmt.Errorf("failed to scan table column: %w", err)
		}
		foundColumns[col] = dtype
	}

	for col, expectedType := range expectedSchema {
		if dtype, ok := foundColumns[col]; !ok || dtype != expectedType {
			return fmt.Errorf("users table has incorrect schema; expected column '%s' of type '%s'", col, expectedType)
		}
	}

	return nil
}

func (s *databaseUserService) createUserTable() error {
	const ddl = `
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password TEXT NOT NULL,
		active BOOLEAN NOT NULL DEFAULT TRUE,
		custom_attributes JSONB NOT NULL DEFAULT '{}'::jsonb
	)`
	_, err := s.db.ExecContext(context.Background(), ddl)
	return err
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
