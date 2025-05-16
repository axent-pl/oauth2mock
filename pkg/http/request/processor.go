package request

import "net/http"

func UnmarshalAndValidate(r *http.Request, dto interface{}) (bool, *Validator) {
	Unmarshal(r, dto)
	validator := NewValidator()
	valid := validator.Validate(dto)
	return valid, validator
}
