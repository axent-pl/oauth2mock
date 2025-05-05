package template

import "io"

type TemplateServicer interface {
	Render(w io.Writer, templateName string, data any) error
}
