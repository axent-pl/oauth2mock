package config

import (
	"errors"
	"os"
	"reflect"
	"strconv"
)

// Load populates a struct with values from environment variables and default tags.
// It supports string, int, float, and boolean field types.
// Tags:
//   - `env:"ENV_VAR_NAME"` specifies the environment variable to read from
//   - `default:"value"` specifies the default value if no environment variable is set
func Load(s interface{}) error {
	// Ensure s is a pointer to a struct
	val := reflect.ValueOf(s)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return errors.New("load requires a pointer to a struct")
	}
	val = val.Elem()
	typ := val.Type()

	// Populate struct fields
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Process default tag
		if defaultValue := fieldType.Tag.Get("default"); defaultValue != "" {
			err := setFieldValue(field, defaultValue)
			if err != nil {
				return err
			}
		}

		// Process env tag
		if envName := fieldType.Tag.Get("env"); envName != "" {
			if value, exists := os.LookupEnv(envName); exists {
				err := setFieldValue(field, value)
				if err != nil {
					return err
				}
			}
		}

	}

	return nil
}

// setFieldValue assigns a string value to a field, converting to the appropriate type.
// Supported types: string, int(8/16/32/64), float(32/64), bool
// Returns an error if the conversion fails or if the field type is unsupported.
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
