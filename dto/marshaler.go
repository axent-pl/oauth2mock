package dto

import (
	"net/http"
	"reflect"
)

func Unmarshal(r *http.Request, s interface{}) {
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		panic("unmarshaling works only works for structs")
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
