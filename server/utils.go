package server

import (
	"net/http"
	"strings"
)

func ParseFormOrMulitForm(r *http.Request, maxMemory int64) error {
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(maxMemory); err != nil {
			return err
		}
	} else if err := r.ParseForm(); err != nil {
		return err
	}
	return nil
}
