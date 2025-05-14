package handler

import (
	"encoding/json"
	"net/http"

	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"golang.org/x/crypto/bcrypt"
)

type SCIMUserDTO struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	UserName    string   `json:"userName"`
	Active      bool     `json:"active"`
	DisplayName string   `json:"displayName"`
}

type SCIMListResponseDTO struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	Resources    []SCIMUserDTO `json:"Resources"`
}

type UserServicer interface {
	GetUsers() ([]UserHandler, error)
}

type UserHandler interface {
	Id() string
	Name() string
	SetPassword(string) error
}

type User struct {
	username     string
	passwordHash string
}

func (u *User) Id() string {
	return u.username
}

func (u *User) Name() string {
	return u.username
}

func (u *User) SetPassword(password string) error {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.passwordHash = string(hashedBytes)
	return nil
}

type UserService struct {
	users []UserHandler
}

func (s *UserService) GetUsers() ([]UserHandler, error) {
	return s.users, nil
}

func SCIMGetHandler(userService UserServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get users from service
		users, err := userService.GetUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// map users to SCIMUserDTO
		var scimUsers []SCIMUserDTO = make([]SCIMUserDTO, len(users))
		for idx, user := range users {
			scimUsers[idx] = SCIMUserDTO{
				Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
				ID:       user.Id(),
				UserName: user.Name(),
			}
		}

		// create SCIM-compliat response
		response := SCIMListResponseDTO{
			Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			TotalResults: len(scimUsers),
			Resources:    scimUsers,
		}

		// Marshal response to JSON
		responseBytes, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Write response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(responseBytes)
	}
}
