package main

import (
	"fmt"
	"net/http"
	"reflect"
)

// ------------------------------

type AuthorizeCredentialsDTO struct {
	Username string `formField:"username" validate:"required"`
	Password string `formField:"password" validate:"required"`
}

type AuthorizeRequestDTO struct {
	ResponseType string `queryParam:"response_type" validate:"required"`
	ClientId     string `queryParam:"client_id" validate:"required"`
	RedirectURI  string `queryParam:"redirect_uri"`
	Scope        string `queryParam:"scope"`
	State        string `queryParam:"state"`
}

type TokenRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id"`
	ClientSecret string `formField:"client_secret"`
	Code         string `formField:"code"`
	RedirectURI  string `formField:"redirect_uri"`
	Username     string `formField:"username"`
	Password     string `formField:"password"`
	RefreshToken string `formField:"refresh_token"`
}

type AuthorizationCodeTokenRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id" validate:"required"`
	ClientSecret string `formField:"client_secret" validate:"required"`
	Code         string `formField:"code" validate:"required"`
	RedirectURI  string `formField:"redirect_uri" validate:"required"`
	Username     string `formField:"username"`
	Password     string `formField:"password"`
	RefreshToken string `formField:"refresh_token"`
}

// ------------------------------

func Hydrate(s interface{}, r *http.Request) {
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		panic("hydration only works for structs")
	}

	typ := val.Type()

	r.ParseMultipartForm(32 << 20)

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		formFieldName := fieldType.Tag.Get("formField")
		if len(formFieldName) > 0 {
			field.SetString(r.PostFormValue(formFieldName))
		}
		queryParamName := fieldType.Tag.Get("queryParam")
		if len(queryParamName) > 0 {
			field.SetString(r.URL.Query().Get(queryParamName))
		}
	}
}

// ------------------------------

type ValidationError struct {
	FiledName    string
	ErrorMessage string
}

type Validator struct {
	Errors map[string]ValidationError
}

func NewValidator() *Validator {
	v := Validator{
		Errors: make(map[string]ValidationError),
	}
	return &v
}

func (v *Validator) Validate(s interface{}) bool {
	v.Errors = make(map[string]ValidationError) // Reset errors before validation

	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		panic("validation only works for structs")
	}

	typ := val.Type()
	isValid := true

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		tag := fieldType.Tag.Get("validate")
		if tag == "required" {
			if isEmptyValue(field) {
				isValid = false
				v.Errors[fieldType.Name] = ValidationError{
					FiledName:    fieldType.Name,
					ErrorMessage: fmt.Sprintf("%s is required", fieldType.Name),
				}
			}
		}
	}

	return isValid
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.Len() == 0
	case reflect.Ptr, reflect.Interface, reflect.Slice, reflect.Map:
		return v.IsNil()
	default:
		return false
	}
}
