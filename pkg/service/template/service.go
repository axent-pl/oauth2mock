package template

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	templateEngine "text/template"
)

type DefaultTemplateService struct {
	templates map[string]templateEngine.Template
}

func NewDefaultTemplateService(templatesPath string) (TemplateServicer, error) {
	ts := &DefaultTemplateService{
		templates: make(map[string]templateEngine.Template),
	}

	err := filepath.Walk(templatesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(info.Name(), ".go.tpl") {
			return nil
		}

		templateName := strings.TrimSuffix(info.Name(), ".go.tpl")

		templateCodeBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		tmpl, err := templateEngine.New(templateName).Parse(string(templateCodeBytes))
		if err != nil {
			return err
		}

		ts.templates[templateName] = *tmpl

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("can not read templates from %s: %w", templatesPath, err)
	}

	return ts, nil
}

func (ts *DefaultTemplateService) Render(w io.Writer, templateName string, data any) error {
	tmpl, ok := ts.templates[templateName]
	if !ok {
		return fmt.Errorf("template %s not found", templateName)
	}

	return tmpl.Execute(w, data)
}
