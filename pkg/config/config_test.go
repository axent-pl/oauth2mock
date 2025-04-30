package config

import (
	"os"
	"testing"
)

type Settings struct {
	KeyFile       string `env:"KEY_PATH" default:"data/key.pem"`
	DataFile      string `env:"DATAFILE_PATH" default:"data/config.json"`
	ServerAddress string `env:"SERVER_ADDRESS" default:":8080"`
	TemplateDir   string `env:"TEMPLATES_PATH" default:"data"`
	UseOrigin     bool   `env:"OAUTH2_ISSUER_FROM_ORIGIN" default:"true"`
	Issuer        string `env:"OAUTH2_ISSUER"`
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected Settings
	}{
		{
			name: "Default values",
			expected: Settings{
				KeyFile:       "data/key.pem",
				DataFile:      "data/config.json",
				ServerAddress: ":8080",
				TemplateDir:   "data",
				UseOrigin:     true,
				Issuer:        "",
			},
		},
		{
			name: "Environment variables",
			envVars: map[string]string{
				"KEY_PATH":                  "/custom/key.pem",
				"DATAFILE_PATH":             "/custom/config.json",
				"SERVER_ADDRESS":            ":9090",
				"TEMPLATES_PATH":            "/custom/templates",
				"OAUTH2_ISSUER_FROM_ORIGIN": "false",
				"OAUTH2_ISSUER":             "https://auth.example.com",
			},
			expected: Settings{
				KeyFile:       "/custom/key.pem",
				DataFile:      "/custom/config.json",
				ServerAddress: ":9090",
				TemplateDir:   "/custom/templates",
				UseOrigin:     false,
				Issuer:        "https://auth.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment before each test
			os.Clearenv()

			// Set environment variables for test
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Create and load settings
			var s Settings
			err := Load(&s)
			if err != nil {
				t.Errorf("Load() error = %v", err)
				return
			}

			// Compare results
			if s.KeyFile != tt.expected.KeyFile {
				t.Errorf("KeyFile = %v, want %v", s.KeyFile, tt.expected.KeyFile)
			}
			if s.DataFile != tt.expected.DataFile {
				t.Errorf("DataFile = %v, want %v", s.DataFile, tt.expected.DataFile)
			}
			if s.ServerAddress != tt.expected.ServerAddress {
				t.Errorf("ServerAddress = %v, want %v", s.ServerAddress, tt.expected.ServerAddress)
			}
			if s.TemplateDir != tt.expected.TemplateDir {
				t.Errorf("TemplateDir = %v, want %v", s.TemplateDir, tt.expected.TemplateDir)
			}
			if s.UseOrigin != tt.expected.UseOrigin {
				t.Errorf("UseOrigin = %v, want %v", s.UseOrigin, tt.expected.UseOrigin)
			}
			if s.Issuer != tt.expected.Issuer {
				t.Errorf("Issuer = %v, want %v", s.Issuer, tt.expected.Issuer)
			}
		})
	}
}

func TestLoadInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
	}{
		{
			name:    "Non-pointer input",
			input:   Settings{},
			wantErr: true,
		},
		{
			name:    "Pointer to non-struct",
			input:   new(string),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Load(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
