package request

import (
	"fmt"
	"reflect"
)

type ValidationError struct {
	FiledName    string
	ErrorMessage string
}

func (ve ValidationError) Error() string {
	return ve.ErrorMessage
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

func (v *Validator) ErrorsList() []error {
	errs := make([]error, 0)
	for _, err := range v.Errors {
		errs = append(errs, err)
	}
	return errs
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
