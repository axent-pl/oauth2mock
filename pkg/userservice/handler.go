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
