package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

// ---------- DTO

type SCIMUserDTO struct {
	Schemas              []string               `json:"schemas"`
	ID                   string                 `json:"id"`
	UserName             string                 `json:"userName"`
	Active               bool                   `json:"active"`
	DisplayName          string                 `json:"displayName"`
	CustomAttributes     map[string]interface{} `json:"urn:example:params:scim:schemas:extension:custom:2.0:User"`
	EnterpriseAttributes map[string]interface{} `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`
}

type SCIMUserCreateRequestDTO struct {
	Schemas              []string               `json:"schemas"`
	ID                   string                 `json:"id"`
	UserName             string                 `json:"userName"`
	Active               bool                   `json:"active"`
	DisplayName          string                 `json:"displayName"`
	Password             string                 `json:"password"`
	CustomAttributes     map[string]interface{} `json:"urn:example:params:scim:schemas:extension:custom:2.0:User"`
	EnterpriseAttributes map[string]interface{} `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`
}

type SCIMListResponseDTO struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	Resources    []SCIMUserDTO `json:"Resources"`
}

// ---------- handlers

func SCIMPostHandler(userService userservice.UserServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler SCIMPostHandler started")
		var userDTO = &SCIMUserCreateRequestDTO{}
		if err := json.NewDecoder(r.Body).Decode(&userDTO); err != nil {
			http.Error(w, "invalid request payload", http.StatusBadRequest)
			return
		}
		if validator := request.NewValidator(); !validator.Validate(userDTO) {
			slog.Error("invalid scim POST request", "validationErrors", validator.Errors)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Validate schemas
		if schemasValid, err := validateSchemas(userDTO.Schemas); !schemasValid {
			slog.Error("invalid SCIM schemas", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Create user credentials
		authScheme, err := authentication.NewScheme(authentication.WithUsernameAndPassword(userDTO.UserName, userDTO.Password))
		if err != nil {
			slog.Error("could not initialize credentials from SCIM input", "error", err)
			http.Error(w, "could not initialize credentials from SCIM input", http.StatusBadRequest)
			return
		}

		// Create a new user
		newUser, err := userservice.NewUserHandler(userDTO.UserName, authScheme, userservice.WithCustomAttributes("custom", userDTO.CustomAttributes), userservice.WithCustomAttributes("enterprise", userDTO.EnterpriseAttributes))
		if err != nil {
			slog.Error("could not initialize user from SCIM input", "error", err)
			http.Error(w, "could not initialize user from SCIM input", http.StatusBadRequest)
			return
		}

		if err = userService.AddUser(newUser); err != nil {
			slog.Error("could not save user", "error", err)
			http.Error(w, "could not save user", http.StatusBadRequest)
			return
		}

		outUserDTO := &SCIMUserDTO{
			Schemas:     userDTO.Schemas,
			ID:          newUser.Id(),
			UserName:    userDTO.UserName,
			Active:      newUser.Active(),
			DisplayName: userDTO.DisplayName,
		}
		if customAttributes := newUser.GetAttributesGroup("custom"); customAttributes != nil {
			outUserDTO.CustomAttributes = customAttributes
		}
		if enterpriseAttributes := newUser.GetAttributesGroup("enterprise"); enterpriseAttributes != nil {
			outUserDTO.EnterpriseAttributes = enterpriseAttributes
		}

		responseBytes, err := json.Marshal(outUserDTO)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(responseBytes)
	}
}

func SCIMGetHandler(userService userservice.UserServicer) routing.HandlerFunc {
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
				Active:   user.Active(),
			}
			if customAttributes := user.GetAttributesGroup("custom"); customAttributes != nil {
				scimUsers[idx].CustomAttributes = customAttributes
			}
			if enterpriseAttributes := user.GetAttributesGroup("enterprise"); enterpriseAttributes != nil {
				scimUsers[idx].EnterpriseAttributes = enterpriseAttributes
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

func validateSchemas(schemas []string) (bool, error) {
	allowed := map[string]bool{
		"urn:ietf:params:scim:schemas:core:2.0:User":                 true,
		"urn:example:params:scim:schemas:extension:custom:2.0:User":  true,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": true,
	}

	foundCore := false
	for _, schema := range schemas {
		if !allowed[schema] {
			return false, fmt.Errorf("invalid SCIM schema %s", schema)
		}
		if schema == "urn:ietf:params:scim:schemas:core:2.0:User" {
			foundCore = true
		}
	}
	if !foundCore {
		return false, errors.New("missing urn:ietf:params:scim:schemas:core:2.0:User schema")
	}

	return true, nil
}
