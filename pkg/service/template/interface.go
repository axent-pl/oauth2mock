package template

import "net/http"

type Service interface {
	Render(w http.ResponseWriter, r *http.Request, templateName string, data any)
}
