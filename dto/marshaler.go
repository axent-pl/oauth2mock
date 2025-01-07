package dto

import (
	"errors"
	"net/http"
	"reflect"
	"strconv"
)

func Unmarshal(r *http.Request, s interface{}) error {
	// Ensure s is a pointer to a struct
	val := reflect.ValueOf(s)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return errors.New("Unmarshal requires a pointer to a struct")
	}
	val = val.Elem()
	typ := val.Type()

	// Parse form data (up to 32 MB)
	r.ParseMultipartForm(32 << 20)

	// Populate struct fields
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Process formField tag
		if formFieldName := fieldType.Tag.Get("formField"); formFieldName != "" {
			if formValue := r.PostFormValue(formFieldName); formValue != "" {
				err := setFieldValue(field, formValue)
				if err != nil {
					return err
				}
			}
		}

		// Process queryParam tag
		if queryParamName := fieldType.Tag.Get("queryParam"); queryParamName != "" {
			if queryValue := r.URL.Query().Get(queryParamName); queryValue != "" {
				err := setFieldValue(field, queryValue)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// setFieldValue assigns a string value to a field, converting to the appropriate type.
func setFieldValue(field reflect.Value, value string) error {
	if !field.CanSet() {
		return errors.New("cannot set value to field")
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			field.SetInt(intValue)
		} else {
			return errors.New("invalid integer value: " + value)
		}
	case reflect.Float32, reflect.Float64:
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			field.SetFloat(floatValue)
		} else {
			return errors.New("invalid float value: " + value)
		}
	case reflect.Bool:
		if boolValue, err := strconv.ParseBool(value); err == nil {
			field.SetBool(boolValue)
		} else {
			return errors.New("invalid boolean value: " + value)
		}
	default:
		return errors.New("unsupported field type")
	}

	return nil
}
