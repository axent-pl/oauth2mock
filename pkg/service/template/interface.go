package template

import "io"

type Service interface {
	Render(w io.Writer, templateName string, data any) error
}
