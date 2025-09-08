package request

import "net/http"

func UnmarshalAndValidate(r *http.Request, dto interface{}) (bool, *Validator) {
	if err := Unmarshal(r, dto); err != nil {
		return false, NewValidator()
	}
	validator := NewValidator()
	valid := validator.Validate(dto)
	return valid, validator
}
